package handler

import (
    "net/http"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"

    "lovewall/internal/auth"
    "lovewall/internal/config"
    basichttp "lovewall/internal/http"
    mw "lovewall/internal/http/middleware"
    "lovewall/internal/model"
)

type AuthHandler struct {
    db  *gorm.DB
    cfg *config.Config
}

func NewAuthHandler(db *gorm.DB, cfg *config.Config) *AuthHandler {
    return &AuthHandler{db: db, cfg: cfg}
}

type RegisterRequest struct {
    Username string `json:"username" binding:"required,min=3,max=32"`
    Password string `json:"password" binding:"required,min=6,max=64"`
}

func (h *AuthHandler) Register(c *gin.Context) {
    var req RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid payload")
        return
    }
    req.Username = strings.TrimSpace(req.Username)
    var count int64
    h.db.Model(&model.User{}).Where("username = ?", req.Username).Count(&count)
    if count > 0 {
        basichttp.Fail(c, http.StatusConflict, "CONFLICT", "username already exists")
        return
    }
    hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    isSuper := false
    // Superadmin bootstrap: if no users exist or matches ADMIN_INIT_USER
    var userCount int64
    h.db.Model(&model.User{}).Count(&userCount)
    if userCount == 0 {
        if h.cfg.AdminInitUser == "" || h.cfg.AdminInitUser == req.Username {
            isSuper = true
        }
    }
    u := &model.User{
        BaseModel:    model.BaseModel{ID: uuid.NewString()},
        Username:     req.Username,
        PasswordHash: string(hashed),
        IsSuperadmin: isSuper,
        Status:       0,
    }
    if err := h.db.Create(u).Error; err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create user")
        return
    }
    token, err := auth.Sign(h.cfg.JWTSecret, u.ID, u.IsSuperadmin, h.cfg.JWTTTL)
    if err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to sign token")
        return
    }
    // Optional cookie
    if h.cfg.CookieName != "" {
        c.SetCookie(h.cfg.CookieName, token, int(h.cfg.JWTTTL), "/", "", true, true)
    }
    basichttp.OK(c, gin.H{"user": sanitizeUser(u), "access_token": token})
}

type LoginRequest struct {
    Username string `json:"username" binding:"required"`
    Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
    var req LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid payload")
        return
    }
    var u model.User
    if err := h.db.Where("username = ? AND deleted_at IS NULL", req.Username).First(&u).Error; err != nil {
        basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
        return
    }
    if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
        basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
        return
    }
    now := time.Now()
    ip := c.ClientIP()
    u.LastLoginAt = &now
    u.LastIP = &ip
    h.db.Model(&u).Updates(map[string]any{"last_login_at": u.LastLoginAt, "last_ip": u.LastIP})

    token, err := auth.Sign(h.cfg.JWTSecret, u.ID, u.IsSuperadmin, h.cfg.JWTTTL)
    if err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to sign token")
        return
    }
    if h.cfg.CookieName != "" {
        c.SetCookie(h.cfg.CookieName, token, int(h.cfg.JWTTTL), "/", "", true, true)
    }
    basichttp.OK(c, gin.H{"user": sanitizeUser(&u), "access_token": token})
}

func (h *AuthHandler) Logout(c *gin.Context) {
    if h.cfg.CookieName != "" {
        c.SetCookie(h.cfg.CookieName, "", -1, "/", "", true, true)
    }
    basichttp.OK(c, gin.H{"ok": true})
}

func (h *AuthHandler) Profile(c *gin.Context) {
    uid, _ := c.Get(mw.CtxUserID)
    var u model.User
    if err := h.db.First(&u, "id = ?", uid).Error; err != nil {
        basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
        return
    }
    // permissions fetch (simple)
    var perms []model.UserPermission
    h.db.Where("user_id = ?", u.ID).Find(&perms)
    pstrs := make([]string, 0, len(perms))
    for _, p := range perms {
        pstrs = append(pstrs, p.Permission)
    }
    basichttp.OK(c, gin.H{"user": sanitizeUser(&u), "permissions": pstrs})
}

func sanitizeUser(u *model.User) gin.H {
    return gin.H{
        "id":            u.ID,
        "username":      u.Username,
        "display_name":  u.DisplayName,
        "email":         u.Email,
        "phone":         u.Phone,
        "avatar_url":    u.AvatarURL,
        "bio":           u.Bio,
        "is_superadmin": u.IsSuperadmin,
        "status":        u.Status,
        "last_login_at": u.LastLoginAt,
        "last_ip":       u.LastIP,
        "metadata":      u.Metadata,
        "created_at":    u.CreatedAt,
        "updated_at":    u.UpdatedAt,
    }
}

