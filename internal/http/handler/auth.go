package handler

import (
    "net/http"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
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
    hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "hash password failed")
        return
    }
    isSuper := false
    // Superadmin bootstrap: if no users exist or matches ADMIN_INIT_USER
    var userCount int64
    h.db.Model(&model.User{}).Count(&userCount)
    if userCount == 0 {
        if h.cfg.AdminInitUser == "" || h.cfg.AdminInitUser == req.Username {
            isSuper = true
        }
    } else if h.cfg.AdminInitUser != "" && h.cfg.AdminInitUser == req.Username && h.cfg.AdminInitPass != "" {
        // Allow creating predefined admin even if users exist, but verify password
        if h.cfg.AdminInitPass == req.Password {
            isSuper = true
        }
    }
    u := &model.User{
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
    h.db.Where("user_id = ? AND deleted_at IS NULL", u.ID).Find(&perms)
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

type UpdateUserRequest struct {
    DisplayName *string `json:"display_name"`
    Email       *string `json:"email"`
    Phone       *string `json:"phone"`
    AvatarURL   *string `json:"avatar_url"`
    Bio         *string `json:"bio"`
    Password    *string `json:"password"`
    OldPassword *string `json:"old_password"`
}

// PUT /api/users/:id (self or MANAGE_USERS)
func (h *AuthHandler) UpdateUser(c *gin.Context) {
    userID := c.Param("id")
    currentUID, _ := c.Get(mw.CtxUserID)
    
    // Check permission: self or MANAGE_USERS
    if userID != currentUID {
        if !mw.IsSuper(c) {
            var cnt int64
            h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL", currentUID, "MANAGE_USERS").Scan(&cnt)
            if cnt == 0 {
                basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
                return
            }
        }
    }
    
    var req UpdateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid payload")
        return
    }
    
    var user model.User
    if err := h.db.First(&user, "id = ? AND deleted_at IS NULL", userID).Error; err != nil {
        basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
        return
    }
    
    updates := make(map[string]interface{})
    
    // Handle password change
    if req.Password != nil {
        if userID == currentUID {
            // Self password change requires old password
            if req.OldPassword == nil {
                basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "old password required")
                return
            }
            if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(*req.OldPassword)) != nil {
                basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid old password")
                return
            }
        }
        hashed, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
        if err != nil {
            basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "hash password failed")
            return
        }
        updates["password_hash"] = string(hashed)
    }
    
    // Handle other fields
    if req.DisplayName != nil {
        updates["display_name"] = req.DisplayName
    }
    if req.Email != nil {
        // Check email uniqueness
        var count int64
        h.db.Model(&model.User{}).Where("email = ? AND id != ? AND deleted_at IS NULL", *req.Email, userID).Count(&count)
        if count > 0 {
            basichttp.Fail(c, http.StatusConflict, "CONFLICT", "email already exists")
            return
        }
        updates["email"] = req.Email
    }
    if req.Phone != nil {
        // Check phone uniqueness
        var count int64
        h.db.Model(&model.User{}).Where("phone = ? AND id != ? AND deleted_at IS NULL", *req.Phone, userID).Count(&count)
        if count > 0 {
            basichttp.Fail(c, http.StatusConflict, "CONFLICT", "phone already exists")
            return
        }
        updates["phone"] = req.Phone
    }
    if req.AvatarURL != nil {
        updates["avatar_url"] = req.AvatarURL
    }
    if req.Bio != nil {
        updates["bio"] = req.Bio
    }
    
    if len(updates) == 0 {
        basichttp.OK(c, sanitizeUser(&user))
        return
    }
    
    if err := h.db.Model(&user).Updates(updates).Error; err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
        return
    }
    
    // Reload user
    if err := h.db.First(&user, "id = ?", userID).Error; err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "reload failed")
        return
    }
    
    basichttp.OK(c, sanitizeUser(&user))
}

