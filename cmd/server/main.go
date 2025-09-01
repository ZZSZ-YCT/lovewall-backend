package main

import (
    "fmt"
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
    "go.uber.org/zap"

    "lovewall/internal/config"
    "lovewall/internal/db"
    "lovewall/internal/http/handler"
    mw "lovewall/internal/http/middleware"
)

func main() {
    cfg := config.Load()
    if cfg.JWTSecret == "" {
        zap.L().Fatal("JWT_SECRET is required; set env JWT_SECRET")
    }

    logger, _ := zap.NewProduction()
    defer logger.Sync()
    zap.ReplaceGlobals(logger)

    database, err := db.Open(cfg)
    if err != nil {
        zap.L().Fatal("failed to open database", zap.Error(err))
    }

    if err := db.AutoMigrate(database); err != nil {
        zap.L().Fatal("failed to run automigrate", zap.Error(err))
    }

    r := gin.New()
    r.Use(gin.Recovery())
    r.Use(mw.RequestLogger())
    if origins := cfg.AllowOrigins; origins != "" {
        r.Use(mw.CORS(strings.Split(origins, ",")))
    }
    // Security headers (lightweight)
    r.Use(func(c *gin.Context) {
        c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
        c.Writer.Header().Set("X-Frame-Options", "DENY")
        c.Next()
    })

    // Serve uploads statically if configured
    if cfg.UploadDir != "" && cfg.UploadBaseURL != "" {
        r.Static(cfg.UploadBaseURL, cfg.UploadDir)
    }

    api := r.Group("/api")

    authH := handler.NewAuthHandler(database, cfg)
    postH := handler.NewPostHandler(database, cfg)
    annH := handler.NewAnnouncementHandler(database, cfg)
    cmtH := handler.NewCommentHandler(database, cfg)
    adminH := handler.NewAdminHandler(database, cfg)

    api.POST("/register", authH.Register)
    api.POST("/login", authH.Login)
    api.POST("/logout", authH.Logout)
    api.GET("/posts", postH.ListPosts)
    api.GET("/posts/:id", postH.GetPost)
    api.GET("/posts/:id/comments", cmtH.ListForPost)
    api.GET("/announcements", annH.List)

    authed := api.Group("")
    authed.Use(mw.RequireAuth(cfg.JWTSecret))
    authed.GET("/profile", authH.Profile)
    authed.POST("/posts", postH.CreatePost)
    authed.PUT("/posts/:id", postH.Update)
    authed.DELETE("/posts/:id", postH.Delete)
    authed.POST("/posts/:id/pin", mw.RequirePerm(database, "PIN_POST"), postH.Pin)
    authed.POST("/posts/:id/feature", mw.RequirePerm(database, "FEATURE_POST"), postH.Feature)
    authed.POST("/posts/:id/hide", mw.RequirePerm(database, "HIDE_POST"), postH.Hide)

    authed.POST("/announcements", mw.RequirePerm(database, "MANAGE_ANNOUNCEMENTS"), annH.Create)
    authed.PUT("/announcements/:id", mw.RequirePerm(database, "MANAGE_ANNOUNCEMENTS"), annH.Update)
    authed.DELETE("/announcements/:id", mw.RequirePerm(database, "MANAGE_ANNOUNCEMENTS"), annH.Delete)

    authed.GET("/users", mw.RequirePerm(database, "MANAGE_USERS"), adminH.ListUsers)
    authed.POST("/users/:id/permissions", adminH.SetUserPermissions)

    authed.POST("/posts/:id/comments", cmtH.Create)
    authed.DELETE("/comments/:id", cmtH.Delete)
    authed.PUT("/comments/:id", cmtH.Update)
    authed.POST("/comments/:id/hide", mw.RequirePerm(database, "MANAGE_COMMENTS"), cmtH.Hide)
    authed.GET("/my/comments", cmtH.ListMine)
    authed.GET("/comments", mw.RequirePerm(database, "MANAGE_COMMENTS"), cmtH.ListModeration)

    addr := fmt.Sprintf(":%d", cfg.Port)
    if err := http.ListenAndServe(addr, r); err != nil {
        zap.L().Fatal("server error", zap.Error(err))
    }
}
