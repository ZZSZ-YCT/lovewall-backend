package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"time"

	"lovewall/internal/config"
	"lovewall/internal/db"
	"lovewall/internal/http/handler"
	mw "lovewall/internal/http/middleware"
	"lovewall/internal/model"
	"lovewall/internal/service"
)

func main() {
	cfg := config.Load()

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

	// Configure AI request limiter from env
	service.InitAILimiter(cfg.AIRateRPS, cfg.AIRateBurst)

	// Cleanup orphaned tag relations to avoid frontend showing ghost "标签"
	service.CleanupOrphanedTagRelations(database)

	cacheSvc := service.NewCacheManager(cfg)

	// Start moderation worker (async AI review)
	service.StartModerationWorker(database, service.NewConfigAdapter(cfg.AIBaseURL, cfg.AIAPIKey, cfg.AIModel))

	// Start heartbeat monitor for user online status tracking
	service.StartHeartbeatMonitor(database)

	// Start async writer for request logs to reduce SQLite write contention
	mw.StartRequestLogWriter(database)

	// Auto-create admin user if configured and no users exist
	if cfg.AdminInitUser != "" && cfg.AdminInitPass != "" {
		var userCount int64
		database.Model(&model.User{}).Count(&userCount)
		if userCount == 0 {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminInitPass), bcrypt.DefaultCost)
			if err != nil {
				zap.L().Fatal("failed to hash admin password", zap.Error(err))
			}

			adminUser := &model.User{
				Username:     cfg.AdminInitUser,
				PasswordHash: string(hashedPassword),
				IsSuperadmin: true,
				Status:       0,
			}

			if err := database.Create(adminUser).Error; err != nil {
				zap.L().Fatal("failed to create admin user", zap.Error(err))
			}

			zap.L().Info("Admin user created successfully", zap.String("username", cfg.AdminInitUser))
		}
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(mw.RequestLogger())
	r.Use(mw.RequestDBLogger(database))
	r.Use(mw.RateLimit(cfg.RateLimitRPS, cfg.RateLimitBurst))
	r.Use(mw.CORS())
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

	authH := handler.NewAuthHandler(database, cfg, cacheSvc)
	postH := handler.NewPostHandler(database, cfg)
	annH := handler.NewAnnouncementHandler(database, cfg)
	cmtH := handler.NewCommentHandler(database, cfg)
	adminH := handler.NewAdminHandler(database, cfg, cacheSvc)
	tagH := handler.NewTagHandler(database, cfg)
	logH := handler.NewLogHandler(database, cfg)
	notifyH := handler.NewNotifyHandler(database, cfg)
	onlineH := handler.NewOnlineHandler(database, cfg)

	api.POST("/register", authH.Register)
	api.POST("/login", authH.Login)
	api.POST("/logout", authH.Logout)
	// Public user lookup endpoints
	api.GET("/users/search", authH.UserList)
	api.GET("/users/:id", authH.GetUserPublicByID)
	api.GET("/users/by-username/:username", authH.GetUserPublicByUsername)
	api.GET("/users/:id/status", authH.GetUserStatusByID)
	api.GET("/users/by-username/:username/status", authH.GetUserStatusByUsername)
	// Public: fetch user's active tag by ID/username
	api.GET("/users/:id/active-tag", authH.GetUserActiveTagByID)
	api.GET("/users/by-username/:username/active-tag", authH.GetUserActiveTagByUsername)
	// Public: fetch user's online status
	api.GET("/users/:id/online", onlineH.GetUserOnlineStatus)
	api.GET("/posts", postH.ListPosts)
	api.GET("/posts/:id", postH.GetPost)
	api.GET("/posts/:id/lock-status", postH.GetPostLockStatus)
	api.GET("/users/:id/posts", postH.ListByUser)
	api.GET("/posts/:id/stats", postH.Stats)
	api.GET("/posts/:id/comments", cmtH.ListForPost)
	api.GET("/announcements", annH.List)
	api.GET("/tags", tagH.ListTags)

	authed := api.Group("")
	authed.Use(mw.RequireAuth(cfg.JWTSecret))
	authed.Use(mw.ValidateSessionAndUser(database))
	authed.GET("/profile", authH.Profile)
	authed.PATCH("/profile", authH.UpdateProfile)
	authed.PUT("/me/password", authH.ChangeMyPassword)
	authed.GET("/users/me/online", authH.OnlineStatus)
	authed.POST("/heartbeat", authH.Heartbeat)
	// Note: Logout is already exposed at /api/logout (public).
	// The handler supports token extraction and blacklist, so a second
	// registration here would duplicate the same route and cause a panic.
	// Therefore, we omit an authenticated duplicate route.
	// Behavior rate-limit (per device/fingerprint/browser) and quotas from env
	authed.POST(
		"/posts",
		mw.LimitAction("post_create", cfg.ActionPostCount, time.Duration(cfg.ActionPostWindowSec)*time.Second),
		mw.EnforcePostDailyQuota(database, cfg.QuotaPostsPerUserPerDay, cfg.QuotaPostsPerIPPerDay),
		postH.CreatePost,
	)
	authed.POST("/posts/:id/request-review", postH.RequestManualReview)
	// Edit post: author within 15min or MANAGE_POSTS
	authed.PUT("/posts/:id", postH.Update)
	authed.DELETE("/posts/:id", postH.Delete)
	authed.POST("/posts/:id/pin", mw.RequirePerm(database, "MANAGE_FEATURED"), postH.Pin)
	authed.POST("/posts/:id/feature", mw.RequirePerm(database, "MANAGE_FEATURED"), postH.Feature)
	authed.POST("/posts/:id/hide", mw.RequirePerm(database, "MANAGE_POSTS"), postH.Hide)
	// Posts moderation list (internal permission checks inside handlers for OR semantics)
	authed.GET("/posts/moderation", postH.ListModeration)

	authed.POST("/announcements", mw.RequirePerm(database, "MANAGE_ANNOUNCEMENTS"), annH.Create)
	authed.GET("/announcements/admin", mw.RequirePerm(database, "MANAGE_ANNOUNCEMENTS"), annH.AdminList)
	authed.PUT("/announcements/:id", mw.RequirePerm(database, "MANAGE_ANNOUNCEMENTS"), annH.Update)
	authed.DELETE("/announcements/:id", mw.RequirePerm(database, "MANAGE_ANNOUNCEMENTS"), annH.Delete)
	authed.POST("/admin/posts/:id/approve", adminH.ApprovePost)
	authed.POST("/admin/posts/:id/reject", adminH.RejectPost)
	authed.POST("/admin/posts/:id/lock", mw.RequirePerm(database, "MANAGE_POSTS"), postH.LockPost)
	authed.POST("/admin/posts/:id/unlock", mw.RequirePerm(database, "MANAGE_POSTS"), postH.UnlockPost)
	authed.POST("/admin/comments/:id/pin", mw.RequirePerm(database, "MANAGE_POSTS"), cmtH.PinComment)
	authed.POST("/admin/comments/:id/unpin", mw.RequirePerm(database, "MANAGE_POSTS"), cmtH.UnpinComment)

	authed.GET("/users", mw.RequirePerm(database, "MANAGE_USERS"), adminH.ListUsers)
	authed.PUT("/users/:id", authH.UpdateUser)
	authed.POST("/users/:id/permissions", adminH.SetUserPermissions)
	authed.PUT("/admin/users/:id/password", adminH.UpdateUserPassword)
	authed.POST("/admin/users/:id/ban", adminH.BanUser)
	authed.POST("/admin/users/:id/unban", adminH.UnbanUser)
	authed.DELETE("/admin/users/:id", adminH.DeleteUser)
	authed.GET("/admin/metrics/overview", adminH.MetricsOverview)

	// Behavior rate-limit and quotas from env
	authed.POST(
		"/posts/:id/comments",
		mw.LimitAction("comment_create", cfg.ActionCommentCount, time.Duration(cfg.ActionCommentWindowSec)*time.Second),
		mw.EnforceCommentHourlyQuota(database, cfg.QuotaCommentsPerUserPerHour, cfg.QuotaCommentsPerIPPerHour),
		cmtH.Create,
	)
	authed.DELETE("/comments/:id", cmtH.Delete)
	// Edit comment: author within 15min or MANAGE_POSTS
	authed.PUT("/comments/:id", cmtH.Update)
	authed.POST("/comments/:id/hide", mw.RequirePerm(database, "MANAGE_POSTS"), cmtH.Hide)
	authed.GET("/my/comments", cmtH.ListMine)
	authed.GET("/comments", mw.RequirePerm(database, "MANAGE_POSTS"), cmtH.ListModeration)

	// Tag and Redemption Code APIs
	authed.POST("/tags", mw.RequirePerm(database, "MANAGE_TAGS"), tagH.CreateTag)
	authed.PUT("/tags/:id", mw.RequirePerm(database, "MANAGE_TAGS"), tagH.UpdateTag)
	authed.DELETE("/tags/:id", mw.RequirePerm(database, "MANAGE_TAGS"), tagH.DeleteTag)
	authed.GET("/tags/:id", tagH.GetTag)

	authed.POST("/tags/generate-codes", mw.RequirePerm(database, "MANAGE_TAGS"), tagH.GenerateRedemptionCodes)
	authed.GET("/redemption-codes", mw.RequirePerm(database, "MANAGE_TAGS"), tagH.ListRedemptionCodes)
	authed.GET("/redemption-codes/by-code/:code", mw.RequirePerm(database, "MANAGE_TAGS"), tagH.GetRedemptionCodeByCode)
	authed.DELETE("/redemption-codes", mw.RequirePerm(database, "MANAGE_TAGS"), tagH.DeleteRedemptionCodes)

	authed.POST("/redeem", tagH.RedeemCode)
	// Admin user tag management
	authed.POST("/admin/users/:id/tags/:tag_id", mw.RequirePerm(database, "MANAGE_TAGS"), tagH.AssignUserTagToUser)
	authed.DELETE("/admin/users/:id/tags/:tag_id", mw.RequirePerm(database, "MANAGE_TAGS"), tagH.RemoveUserTagFromUser)
	authed.GET("/admin/users/:id/tags", mw.RequirePerm(database, "MANAGE_TAGS"), tagH.AdminListUserTags)
	// Admin logs (superadmin only; enforced inside handlers)
	authed.GET("/admin/logs/submissions", logH.ListSubmissionLogs)
	authed.GET("/admin/logs/operations", logH.ListOperationLogs)
	authed.GET("/my/tags", tagH.ListUserTags)
	authed.GET("/my/tags/active", tagH.GetMyActiveTags)
	authed.GET("/my/tags/current-status", tagH.MyCurrentTagStatus)
	authed.GET("/my/tags/:tag_id/status", tagH.MyTagStatusByTagID)
	authed.POST("/my/tags/:tag_id/activate", tagH.SetActiveTag)
	authed.DELETE("/my/tags/:tag_id/activate", tagH.DeactivateTag)
	// Notifications
	authed.GET("/notifications", notifyH.List)
	authed.GET("/notifications/unread-count", notifyH.UnreadCount)
	authed.POST("/notifications/:id/read", notifyH.MarkRead)

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	if err := http.ListenAndServe(addr, r); err != nil {
		zap.L().Fatal("server error", zap.Error(err))
	}
}
