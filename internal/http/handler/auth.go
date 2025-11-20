package handler

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"lovewall/internal/auth"
	"lovewall/internal/config"
	basichttp "lovewall/internal/http"
	mw "lovewall/internal/http/middleware"
	"lovewall/internal/model"
	"lovewall/internal/service"
	"lovewall/internal/storage"
)

type AuthHandler struct {
	db         *gorm.DB
	cfg        *config.Config
	cache      service.Cache
	captchaSvc *service.CaptchaService
}

func NewAuthHandler(db *gorm.DB, cfg *config.Config, cache service.Cache, captchaSvc *service.CaptchaService) *AuthHandler {
	return &AuthHandler{db: db, cfg: cfg, cache: cache, captchaSvc: captchaSvc}
}

func (h *AuthHandler) ensureCaptcha(c *gin.Context, captchaID string, payload service.VerifyPayload) bool {
	if h.captchaSvc == nil {
		zap.L().Error("captcha service not initialized")
		basichttp.Fail(c, http.StatusInternalServerError, "CAPTCHA_FAILED", "验证码校验失败")
		return false
	}

	if err := h.captchaSvc.Verify(captchaID, payload); err != nil {
		switch {
		case errors.Is(err, service.ErrCaptchaRequired):
			basichttp.Fail(c, http.StatusBadRequest, "CAPTCHA_REQUIRED", "验证码不能为空")
		case errors.Is(err, service.ErrCaptchaInvalid):
			basichttp.Fail(c, http.StatusBadRequest, "CAPTCHA_INVALID", "验证码无效或已过期")
		case errors.Is(err, service.ErrCaptchaFailed):
			basichttp.Fail(c, http.StatusBadRequest, "CAPTCHA_FAILED", "验证码校验失败")
		default:
			zap.L().Error("captcha verification error", zap.Error(err))
			basichttp.Fail(c, http.StatusInternalServerError, "CAPTCHA_FAILED", "验证码校验失败")
		}
		return false
	}
	return true
}

type RegisterRequest struct {
	Username    string             `json:"username" binding:"required,min=3,max=32"`
	Password    string             `json:"password" binding:"required,min=6,max=64"`
	CaptchaID   string             `json:"captcha_id" binding:"required"`
	CaptchaData json.RawMessage    `json:"captcha_data"`
	Dots        []service.DotInput `json:"dots"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid payload")
		return
	}
	if !h.ensureCaptcha(c, req.CaptchaID, service.VerifyPayload{Raw: req.CaptchaData, Dots: req.Dots}) {
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
	// Record registration time and IP
	now := time.Now()
	ip := c.ClientIP()
	u := &model.User{
		Username:     req.Username,
		PasswordHash: string(hashed),
		IsSuperadmin: isSuper,
		Status:       0,
		LastLoginAt:  &now,
		LastIP:       &ip,
	}
	if err := h.db.Create(u).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create user")
		return
	}
	token, jti, err := auth.SignWithJTI(h.cfg.JWTSecret, u.ID, u.IsSuperadmin, h.cfg.JWTTTL)
	if err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to sign token")
		return
	}
	// Create session and enforce 2-device limit
	if err := h.createSessionAndEnforceLimit(c, u.ID, jti); err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to persist session")
		return
	}
	// Optional cookie
	if h.cfg.CookieName != "" {
		c.SetCookie(h.cfg.CookieName, token, int(h.cfg.JWTTTL), "/", "", true, true)
	}
	basichttp.OK(c, gin.H{"user": sanitizeUser(h.db, u), "access_token": token})
}

type LoginRequest struct {
	Username    string             `json:"username" binding:"required"`
	Password    string             `json:"password" binding:"required"`
	CaptchaID   string             `json:"captcha_id" binding:"required"`
	CaptchaData json.RawMessage    `json:"captcha_data"`
	Dots        []service.DotInput `json:"dots"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid payload")
		return
	}
	if !h.ensureCaptcha(c, req.CaptchaID, service.VerifyPayload{Raw: req.CaptchaData, Dots: req.Dots}) {
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
	if u.IsBanned {
		reason := "account has been banned"
		if u.BanReason != nil && *u.BanReason != "" {
			reason = *u.BanReason
		}
		basichttp.FailWithExtras(c, http.StatusForbidden, "BANNED", reason, gin.H{"banned": true, "ban_reason": reason})
		return
	}
	now := time.Now()
	ip := c.ClientIP()
	u.LastLoginAt = &now
	u.LastIP = &ip
	h.db.Model(&u).Updates(map[string]any{"last_login_at": u.LastLoginAt, "last_ip": u.LastIP})

	token, jti, err := auth.SignWithJTI(h.cfg.JWTSecret, u.ID, u.IsSuperadmin, h.cfg.JWTTTL)
	if err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to sign token")
		return
	}
	// Create session and enforce 2-device limit
	if err := h.createSessionAndEnforceLimit(c, u.ID, jti); err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to persist session")
		return
	}
	if h.cfg.CookieName != "" {
		c.SetCookie(h.cfg.CookieName, token, int(h.cfg.JWTTTL), "/", "", true, true)
	}
	basichttp.OK(c, gin.H{"user": sanitizeUser(h.db, &u), "access_token": token})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	// Attempt to blacklist current token if present
	tokenStr := ""
	if v, ok := c.Get(mw.CtxTokenStr); ok {
		if s, ok2 := v.(string); ok2 {
			tokenStr = s
		}
	}
	if tokenStr == "" {
		// fallback to header/cookie parse (route may be unauthenticated)
		hdr := c.GetHeader("Authorization")
		if strings.HasPrefix(strings.ToLower(hdr), "bearer ") {
			tokenStr = strings.TrimSpace(hdr[7:])
		}
		if tokenStr == "" && h.cfg.CookieName != "" {
			if ck, err := c.Cookie(h.cfg.CookieName); err == nil {
				tokenStr = ck
			}
		}
	}
	if tokenStr != "" {
		// Parse to obtain expiration and JTI
		token, err := jwtParseWithUserClaims(h.cfg.JWTSecret, tokenStr)
		if err == nil && token.Valid {
			if claims, ok := token.Claims.(*mw.UserClaims); ok {
				// Remove session by JTI
				if claims.ID != "" {
					_ = h.db.Where("jti = ?", claims.ID).Delete(&model.UserSession{}).Error
				}
				if claims.ExpiresAt != nil {
					mw.AddTokenToBlacklist(tokenStr, claims.ExpiresAt.Time)
				}
			}
		}
	}
	if h.cfg.CookieName != "" {
		c.SetCookie(h.cfg.CookieName, "", -1, "/", "", true, true)
	}
	basichttp.OK(c, gin.H{"ok": true})
}

// Change password for current user
type changePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6,max=64"`
}

// PUT /api/me/password (auth)
func (h *AuthHandler) ChangeMyPassword(c *gin.Context) {
	uidVal, _ := c.Get(mw.CtxUserID)
	userID := uidVal.(string)
	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid payload")
		return
	}
	var user model.User
	if err := h.db.First(&user, "id = ? AND deleted_at IS NULL", userID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)) != nil {
		basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid old password")
		return
	}
	if err := validateNewPassword(req.NewPassword, &user, req.OldPassword); err != nil {
		basichttp.Fail(c, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "hash password failed")
		return
	}
	if err := h.db.Model(&user).Update("password_hash", string(hashed)).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	// Revoke all sessions immediately after password change
	_ = h.db.Where("user_id = ?", userID).Delete(&model.UserSession{}).Error
	c.Status(http.StatusNoContent)
}

// GET /api/users/me/online (auth) — online status based on heartbeat
func (h *AuthHandler) OnlineStatus(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	var u model.User
	if err := h.db.Select("is_online, last_heartbeat").First(&u, "id = ?", uid).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	resp := gin.H{
		"online":         u.IsOnline,
		"last_heartbeat": u.LastHeartbeat,
	}
	if v, ok := c.Get(mw.CtxTokenExp); ok {
		if t, ok2 := v.(time.Time); ok2 {
			resp["expires_at"] = t
			resp["token_expires_at"] = t
		}
	}
	basichttp.OK(c, resp)
}

// POST /api/heartbeat (auth) — update user heartbeat and return unread notification count
func (h *AuthHandler) Heartbeat(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	now := time.Now()
	if err := h.db.Model(&model.User{}).Where("id = ?", uid).Updates(map[string]any{
		"is_online":      true,
		"last_heartbeat": now,
	}).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "heartbeat update failed")
		return
	}

	// Query unread notification count
	var unreadCount int64
	if err := h.db.Model(&model.Notification{}).
		Where("user_id = ? AND is_read = ? AND deleted_at IS NULL", uid, false).
		Count(&unreadCount).Error; err != nil {
		// Don't fail the whole request if notification query fails
		unreadCount = 0
	}

	basichttp.OK(c, gin.H{
		"online":               true,
		"timestamp":            now,
		"unread_notifications": unreadCount,
	})
}

// helpers
func validateNewPassword(newPwd string, user *model.User, oldPlain string) error {
	if len(newPwd) < 6 {
		return errors.New("password too short")
	}
	if oldPlain != "" && newPwd == oldPlain {
		return errors.New("new password must differ from old")
	}
	return nil
}

// Parse token using middleware claims to access expiration
func jwtParseWithUserClaims(secret, tokenStr string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenStr, &mw.UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
}

// createSessionAndEnforceLimit records a session for the user and enforces a maximum of 2 active sessions.
func (h *AuthHandler) createSessionAndEnforceLimit(c *gin.Context, userID, jti string) error {
	ua := c.Request.UserAgent()
	ip := c.ClientIP()
	uaPtr, ipPtr := (*string)(nil), (*string)(nil)
	if ua != "" {
		uaPtr = &ua
	}
	if ip != "" {
		ipPtr = &ip
	}
	// Compute expiration aligned with JWT TTL
	exp := time.Now().Add(time.Duration(h.cfg.JWTTTL) * time.Second)

	sess := &model.UserSession{
		UserID:    userID,
		JTI:       jti,
		ExpiresAt: exp,
		IP:        ipPtr,
		UserAgent: uaPtr,
	}
	if err := h.db.Create(sess).Error; err != nil {
		return err
	}
	// Enforce at most 2 sessions per user by deleting older ones
	var ids []string
	// Fetch IDs after the first 2 most recent sessions
	h.db.Model(&model.UserSession{}).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Offset(2).
		Pluck("id", &ids)
	if len(ids) > 0 {
		_ = h.db.Where("id IN ?", ids).Delete(&model.UserSession{}).Error
	}
	return nil
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
	basichttp.OK(c, gin.H{"user": sanitizeUser(h.db, &u), "permissions": pstrs})
}

// hasAnyAdminPermission checks if user has superadmin flag or any permission
func hasAnyAdminPermission(db *gorm.DB, userID string) bool {
	var u model.User
	if err := db.Select("is_superadmin").First(&u, "id = ? AND deleted_at IS NULL", userID).Error; err != nil {
		return false
	}
	if u.IsSuperadmin {
		return true
	}
	var cnt int64
	db.Model(&model.UserPermission{}).Where("user_id = ? AND deleted_at IS NULL", userID).Count(&cnt)
	return cnt > 0
}

// hasAnyAdminPermissionCached checks admin status using pre-fetched user and permission data.
func hasAnyAdminPermissionCached(user *model.User, hasPermission bool) bool {
	if user == nil {
		return false
	}
	if user.IsSuperadmin {
		return true
	}
	return hasPermission
}

// batchQueryAdminStatus fetches user admin indicators in a single pass.
func batchQueryAdminStatus(db *gorm.DB, userIDs []string) (map[string]*model.User, map[string]bool, error) {
	userMap := make(map[string]*model.User)
	permMap := make(map[string]bool)
	if len(userIDs) == 0 {
		return userMap, permMap, nil
	}

	uniqueIDs := make([]string, 0, len(userIDs))
	seen := make(map[string]struct{}, len(userIDs))
	for _, id := range userIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		uniqueIDs = append(uniqueIDs, id)
	}
	if len(uniqueIDs) == 0 {
		return userMap, permMap, nil
	}

	var users []model.User
	if err := db.Select("id, username, display_name, is_superadmin").
		Where("id IN ? AND deleted_at IS NULL", uniqueIDs).
		Find(&users).Error; err != nil {
		return nil, nil, err
	}
	for i := range users {
		userMap[users[i].ID] = &users[i]
	}

	type permCount struct {
		UserID string
		Count  int64
	}
	var permCounts []permCount
	if err := db.Model(&model.UserPermission{}).
		Select("user_id, COUNT(*) as count").
		Where("user_id IN ? AND deleted_at IS NULL", uniqueIDs).
		Group("user_id").
		Scan(&permCounts).Error; err != nil {
		return nil, nil, err
	}
	for _, pc := range permCounts {
		permMap[pc.UserID] = pc.Count > 0
	}

	return userMap, permMap, nil
}

func sanitizeUser(db *gorm.DB, u *model.User) gin.H {
	result := sanitizeUserCached(u, hasAnyAdminPermission(db, u.ID))

	// Add active tag
	tagService := service.NewUserTagService(db)
	tag, _ := tagService.GetActiveUserTag(u.ID)
	if tag != nil {
		result["active_tag"] = gin.H{
			"id":               tag.ID,
			"name":             tag.Name,
			"title":            tag.Title,
			"background_color": tag.BackgroundColor,
			"text_color":       tag.TextColor,
			"tag_type":         tag.TagType,
			"css_styles":       tag.CssStyles,
		}
	} else {
		result["active_tag"] = nil
	}

	return result
}

// sanitizeUserCached formats user data using a precomputed admin flag.
func sanitizeUserCached(u *model.User, isAdmin bool) gin.H {
	if u == nil {
		return gin.H{}
	}
	return gin.H{
		"id":             u.ID,
		"username":       u.Username,
		"display_name":   u.DisplayName,
		"email":          u.Email,
		"phone":          u.Phone,
		"avatar_url":     u.AvatarURL,
		"bio":            u.Bio,
		"is_superadmin":  u.IsSuperadmin,
		"status":         u.Status,
		"is_banned":      u.IsBanned,
		"ban_reason":     u.BanReason,
		"last_login_at":  u.LastLoginAt,
		"last_ip":        u.LastIP,
		"is_online":      u.IsOnline,
		"last_heartbeat": u.LastHeartbeat,
		"metadata":       u.Metadata,
		"created_at":     u.CreatedAt,
		"updated_at":     u.UpdatedAt,
		"is_deleted":     u.DeletedAt != nil,
		"is_admin":       isAdmin,
	}
}

// Public-facing user response (no email/phone/sensitive fields)
func sanitizeUserPublic(db *gorm.DB, u *model.User) gin.H {
	if u.IsBanned {
		result := gin.H{
			"id":         u.ID,
			"username":   u.Username,
			"is_banned":  true,
			"is_deleted": u.DeletedAt != nil,
			"is_admin":   hasAnyAdminPermission(db, u.ID),
		}
		// Add active tag even for banned users
		tagService := service.NewUserTagService(db)
		tag, _ := tagService.GetActiveUserTag(u.ID)
		if tag != nil {
			result["active_tag"] = gin.H{
				"id":               tag.ID,
				"name":             tag.Name,
				"title":            tag.Title,
				"background_color": tag.BackgroundColor,
				"text_color":       tag.TextColor,
				"tag_type":         tag.TagType,
				"css_styles":       tag.CssStyles,
			}
		} else {
			result["active_tag"] = nil
		}
		return result
	}

	result := gin.H{
		"id":             u.ID,
		"username":       u.Username,
		"display_name":   u.DisplayName,
		"avatar_url":     u.AvatarURL,
		"status":         u.Status,
		"is_online":      u.IsOnline,
		"last_heartbeat": u.LastHeartbeat,
		"created_at":     u.CreatedAt,
		"updated_at":     u.UpdatedAt,
		"is_deleted":     u.DeletedAt != nil,
		"is_admin":       hasAnyAdminPermission(db, u.ID),
	}

	// Add active tag
	tagService := service.NewUserTagService(db)
	tag, _ := tagService.GetActiveUserTag(u.ID)
	if tag != nil {
		result["active_tag"] = gin.H{
			"id":               tag.ID,
			"name":             tag.Name,
			"title":            tag.Title,
			"background_color": tag.BackgroundColor,
			"text_color":       tag.TextColor,
			"tag_type":         tag.TagType,
			"css_styles":       tag.CssStyles,
		}
	} else {
		result["active_tag"] = nil
	}

	return result
}

func sanitizeUserPublicList(u *model.User) gin.H {
	var displayName any
	if u.DisplayName != nil {
		displayName = *u.DisplayName
	}
	return gin.H{
		"id":           u.ID,
		"username":     u.Username,
		"display_name": displayName,
	}
}

type UpdateUserRequest struct {
	Username     *string `json:"username"`
	DisplayName  *string `json:"display_name"`
	Email        *string `json:"email"`
	Phone        *string `json:"phone"`
	AvatarURL    *string `json:"avatar_url"`
	AvatarBase64 *string `json:"avatar_base64"`
	Bio          *string `json:"bio"`
	Password     *string `json:"password"`
	OldPassword  *string `json:"old_password"`
}

// PUT /api/users/:id (self or MANAGE_USERS)
func (h *AuthHandler) UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	currentUID, _ := c.Get(mw.CtxUserID)

	// Check permission: self or MANAGE_USERS
	isSelf := userID == currentUID
	hasManageUsers := false
	if mw.IsSuper(c, h.db) {
		hasManageUsers = true
	} else {
		var cnt int64
		h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL", currentUID, "MANAGE_USERS").Scan(&cnt)
		hasManageUsers = cnt > 0
	}
	if !isSelf && !hasManageUsers {
		basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
		return
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
	previousUsername := user.Username

	// Prevent non-superadmin from modifying superadmin accounts
	if user.IsSuperadmin && !isSelf {
		var currentUser model.User
		if err := h.db.Select("is_superadmin").First(&currentUser, "id = ?", currentUID).Error; err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "permission check failed")
			return
		}
		if !currentUser.IsSuperadmin {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "cannot modify superadmin")
			return
		}
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
	if req.Username != nil {
		if !hasManageUsers { // only admins with MANAGE_USERS (or super) may change username
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "username change requires MANAGE_USERS")
			return
		}
		uname := strings.TrimSpace(*req.Username)
		if len(uname) < 3 || len(uname) > 32 {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "username length must be 3-32")
			return
		}
		var count int64
		h.db.Model(&model.User{}).Where("username = ? AND id != ? AND deleted_at IS NULL", uname, userID).Count(&count)
		if count > 0 {
			basichttp.Fail(c, http.StatusConflict, "CONFLICT", "username already exists")
			return
		}
		updates["username"] = uname
	}
	if req.DisplayName != nil {
		if strings.TrimSpace(*req.DisplayName) == "" {
			updates["display_name"] = nil
		} else {
			updates["display_name"] = req.DisplayName
		}
	}
	if req.Email != nil {
		email := strings.TrimSpace(*req.Email)
		if email == "" {
			// Allow clearing email
			updates["email"] = nil
		} else {
			// Check email uniqueness
			var count int64
			h.db.Model(&model.User{}).Where("email = ? AND id != ? AND deleted_at IS NULL", email, userID).Count(&count)
			if count > 0 {
				basichttp.Fail(c, http.StatusConflict, "CONFLICT", "email already exists")
				return
			}
			updates["email"] = &email
		}
	}
	if req.Phone != nil {
		phone := strings.TrimSpace(*req.Phone)
		if phone == "" {
			// Allow clearing phone
			updates["phone"] = nil
		} else {
			// Check phone uniqueness
			var count int64
			h.db.Model(&model.User{}).Where("phone = ? AND id != ? AND deleted_at IS NULL", phone, userID).Count(&count)
			if count > 0 {
				basichttp.Fail(c, http.StatusConflict, "CONFLICT", "phone already exists")
				return
			}
			updates["phone"] = &phone
		}
	}
	if req.AvatarURL != nil {
		if strings.TrimSpace(*req.AvatarURL) == "" {
			updates["avatar_url"] = nil
		} else {
			updates["avatar_url"] = req.AvatarURL
		}
	}
	if req.Bio != nil {
		if strings.TrimSpace(*req.Bio) == "" {
			updates["bio"] = nil
		} else {
			updates["bio"] = req.Bio
		}
	}

	// Handle avatar base64 upload (admin/self)
	var oldAvatarPathToDelete string
	if req.AvatarBase64 != nil && *req.AvatarBase64 != "" {
		s := *req.AvatarBase64
		if !strings.HasPrefix(s, "data:image/") || !strings.Contains(s, ";base64,") {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid avatar base64 format")
			return
		}
		parts := strings.SplitN(s, ",", 2)
		if len(parts) != 2 {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid avatar base64 format")
			return
		}
		meta, b64 := parts[0], parts[1]
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid base64 data")
			return
		}
		if int64(len(raw)) > int64(h.cfg.MaxUploadMB)*1024*1024 {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "avatar too large")
			return
		}
		mime := ""
		if idx := strings.Index(meta, ":"); idx >= 0 {
			if j := strings.Index(meta[idx+1:], ";"); j >= 0 {
				mime = meta[idx+1 : idx+1+j]
			}
		}
		if mime == "" {
			mime = http.DetectContentType(raw)
		}
		ext := storage.ExtFromMIME(mime)
		if ext == "" {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "unsupported avatar format")
			return
		}
		// Save new avatar
		ts := time.Now().UnixMilli()
		savedName := filepath.ToSlash(filepath.Join("avatars", userID+"-"+fmtInt64(ts)+ext))
		lp := &storage.LocalProvider{BaseDir: h.cfg.UploadDir}
		if _, err := lp.Save(c, bytes.NewReader(raw), savedName); err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "save avatar failed")
			return
		}
		url := storage.JoinURL(h.cfg.UploadBaseURL, savedName)
		updates["avatar_url"] = &url
		// Prepare deletion of previous avatar (after successful DB update)
		if user.AvatarURL != nil && *user.AvatarURL != "" {
			rel := strings.TrimPrefix(*user.AvatarURL, h.cfg.UploadBaseURL)
			if strings.HasPrefix(rel, "/") {
				rel = rel[1:]
			}
			oldPath := filepath.Join(h.cfg.UploadDir, rel)
			base := filepath.Clean(h.cfg.UploadDir)
			target := filepath.Clean(oldPath)
			if strings.HasPrefix(target, base+string(os.PathSeparator)) || target == base {
				oldAvatarPathToDelete = target
			}
		}
	}

	if len(updates) == 0 {
		basichttp.OK(c, sanitizeUser(h.db, &user))
		return
	}

	if err := h.db.Model(&user).Updates(updates).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	// If password or username changed by admin/self, revoke all sessions
	if _, ok := updates["password_hash"]; ok {
		_ = h.db.Where("user_id = ?", userID).Delete(&model.UserSession{}).Error
	}
	if _, ok := updates["username"]; ok {
		_ = h.db.Where("user_id = ?", userID).Delete(&model.UserSession{}).Error
	}

	// Reload user
	if err := h.db.First(&user, "id = ?", userID).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "reload failed")
		return
	}
	// Best-effort delete of previous avatar
	if oldAvatarPathToDelete != "" {
		_ = os.Remove(oldAvatarPathToDelete)
	}

	ctxReq := c.Request.Context()
	publicPayload := sanitizeUserPublic(h.db, &user)
	h.invalidateUserCache(ctxReq, user.ID, previousUsername, user.Username)
	h.cacheUserPublic(ctxReq, &user, publicPayload)

	// Log admin operation if editing others or changing username as admin
	if !isSelf && hasManageUsers {
		if uidVal, ok := c.Get(mw.CtxUserID); ok {
			if uidStr, ok2 := uidVal.(string); ok2 {
				// Collect changed fields for audit
				fields := make([]string, 0, len(updates))
				for k := range updates {
					fields = append(fields, k)
				}
				meta := map[string]any{"fields": fields}
				service.LogOperation(h.db, uidStr, "update_user", "user", userID, meta)
			}
		}
	}
	basichttp.OK(c, sanitizeUser(h.db, &user))
}

// PATCH /api/profile (auth)
// Updates current user's profile, including optional Base64 avatar upload.
type UpdateProfileRequest struct {
	DisplayName  *string `json:"display_name"`
	Email        *string `json:"email"`
	Phone        *string `json:"phone"`
	Bio          *string `json:"bio"`
	AvatarBase64 *string `json:"avatar_base64"`
}

func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	uidVal, _ := c.Get(mw.CtxUserID)
	userID := uidVal.(string)

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid payload")
		return
	}

	// Fetch current user
	var user model.User
	if err := h.db.First(&user, "id = ? AND deleted_at IS NULL", userID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	// Prepare updates map and validations
	updates := make(map[string]any)
	// Validations
	if req.DisplayName != nil {
		if len(*req.DisplayName) > 100 {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "display_name too long")
			return
		}
	}
	if req.Bio != nil {
		if len(*req.Bio) > 500 {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "bio too long")
			return
		}
	}
	if req.Email != nil {
		v := strings.TrimSpace(*req.Email)
		if v == "" {
			// treat empty as NULL
			updates["email"] = nil
		} else {
			// simple email regex
			emailRe := regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
			if !emailRe.MatchString(v) {
				basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "Email format is invalid")
				return
			}
			// Check uniqueness (exclude self)
			var cnt int64
			h.db.Model(&model.User{}).Where("email = ? AND id != ? AND deleted_at IS NULL", v, userID).Count(&cnt)
			if cnt > 0 {
				basichttp.Fail(c, http.StatusConflict, "CONFLICT", "email already exists")
				return
			}
			// assign normalized value
			req.Email = &v
		}
	}
	if req.Phone != nil {
		v := strings.TrimSpace(*req.Phone)
		if v == "" {
			// treat empty as NULL
			updates["phone"] = nil
		} else {
			phoneRe := regexp.MustCompile(`^1[3-9]\d{9}$`)
			if !phoneRe.MatchString(v) {
				basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "Phone format is invalid")
				return
			}
			var cnt int64
			h.db.Model(&model.User{}).Where("phone = ? AND id != ? AND deleted_at IS NULL", v, userID).Count(&cnt)
			if cnt > 0 {
				basichttp.Fail(c, http.StatusConflict, "CONFLICT", "phone already exists")
				return
			}
			req.Phone = &v
		}
	}

	if req.DisplayName != nil {
		if strings.TrimSpace(*req.DisplayName) == "" {
			updates["display_name"] = nil
		} else {
			updates["display_name"] = req.DisplayName
		}
	}
	if req.Bio != nil {
		if strings.TrimSpace(*req.Bio) == "" {
			updates["bio"] = nil
		} else {
			updates["bio"] = req.Bio
		}
	}
	if req.Email != nil {
		v := strings.TrimSpace(*req.Email)
		if v == "" {
			updates["email"] = nil
		} else {
			updates["email"] = req.Email
		}
	}
	if req.Phone != nil {
		v := strings.TrimSpace(*req.Phone)
		if v == "" {
			updates["phone"] = nil
		} else {
			updates["phone"] = req.Phone
		}
	}

	// Handle avatar upload if provided
	var oldAvatarPathToDelete string
	if req.AvatarBase64 != nil && *req.AvatarBase64 != "" {
		s := *req.AvatarBase64
		if !strings.HasPrefix(s, "data:image/") || !strings.Contains(s, ";base64,") {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid avatar base64 format")
			return
		}
		parts := strings.SplitN(s, ",", 2)
		if len(parts) != 2 {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid avatar base64 format")
			return
		}
		dataPart := parts[1]
		// remove whitespace/newlines
		dataPart = strings.TrimSpace(dataPart)
		raw, err := base64.StdEncoding.DecodeString(dataPart)
		if err != nil {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid base64 data")
			return
		}
		if len(raw) > 5*1024*1024 {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "avatar too large (max 5MB)")
			return
		}
		// Detect MIME from bytes
		probe := raw
		if len(probe) > 512 {
			probe = probe[:512]
		}
		mime := http.DetectContentType(probe)
		ext := storage.ExtFromMIME(mime)
		if ext == "" {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "unsupported avatar format")
			return
		}
		// Save new avatar
		ts := time.Now().UnixMilli()
		savedName := filepath.ToSlash(filepath.Join("avatars", userID+"-"+fmtInt64(ts)+ext))
		lp := &storage.LocalProvider{BaseDir: h.cfg.UploadDir}
		if _, err := lp.Save(c, bytes.NewReader(raw), savedName); err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "save avatar failed")
			return
		}
		url := storage.JoinURL(h.cfg.UploadBaseURL, savedName)
		updates["avatar_url"] = &url
		// Prepare deletion of previous avatar (after successful DB update)
		if user.AvatarURL != nil && *user.AvatarURL != "" {
			rel := strings.TrimPrefix(*user.AvatarURL, h.cfg.UploadBaseURL)
			if strings.HasPrefix(rel, "/") {
				rel = rel[1:]
			}
			oldPath := filepath.Join(h.cfg.UploadDir, rel)
			base := filepath.Clean(h.cfg.UploadDir)
			target := filepath.Clean(oldPath)
			if strings.HasPrefix(target, base+string(os.PathSeparator)) || target == base {
				oldAvatarPathToDelete = target
			}
		}
	}

	if len(updates) == 0 {
		basichttp.OK(c, sanitizeUser(h.db, &user))
		return
	}
	if err := h.db.Model(&user).Updates(updates).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	if err := h.db.First(&user, "id = ?", userID).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "reload failed")
		return
	}
	ctxReq := c.Request.Context()
	publicPayload := sanitizeUserPublic(h.db, &user)
	h.invalidateUserCache(ctxReq, user.ID, user.Username)
	h.cacheUserPublic(ctxReq, &user, publicPayload)
	// Best-effort delete of previous avatar
	if oldAvatarPathToDelete != "" {
		_ = os.Remove(oldAvatarPathToDelete)
	}
	basichttp.OK(c, sanitizeUser(h.db, &user))
}

func fmtInt64(i int64) string { return strconv.FormatInt(i, 10) }

// GET /api/users/:id (public) — basic profile for avatar/nickname lookups
func (h *AuthHandler) GetUserPublicByID(c *gin.Context) {
	id := c.Param("id")

	// Handle AI system user query
	if id == model.AI_SYSTEM_UUID {
		basichttp.OK(c, gin.H{
			"id":         model.AI_SYSTEM_UUID,
			"username":   "AI审核系统",
			"is_banned":  false,
			"is_deleted": false,
			"created_at": time.Time{},
		})
		return
	}

	ctx := c.Request.Context()
	var cached map[string]any
	if ok, err := h.readJSONFromCache(ctx, userCacheKeyByID(id), &cached); err == nil && ok {
		basichttp.OK(c, cached)
		return
	} else if err != nil {
		zap.L().Warn("failed to read user cache by id", zap.Error(err))
	}

	var u model.User
	if err := h.db.Unscoped().First(&u, "id = ?", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	payload := sanitizeUserPublic(h.db, &u)
	basichttp.OK(c, payload)
	h.cacheUserPublic(ctx, &u, payload)
}

// GET /api/users/by-username/:username (public)
func (h *AuthHandler) GetUserPublicByUsername(c *gin.Context) {
	uname := c.Param("username")

	ctx := c.Request.Context()
	var cached map[string]any
	if ok, err := h.readJSONFromCache(ctx, userCacheKeyByUsername(uname), &cached); err == nil && ok {
		basichttp.OK(c, cached)
		return
	} else if err != nil {
		zap.L().Warn("failed to read user cache by username", zap.Error(err))
	}

	var u model.User
	if err := h.db.Unscoped().First(&u, "username = ?", uname).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	payload := sanitizeUserPublic(h.db, &u)
	basichttp.OK(c, payload)
	h.cacheUserPublic(ctx, &u, payload)
}

const (
	userListDefaultPage          = 1
	userListDefaultPageSize      = 20
	userListMaxPageSize          = 200
	userListMaxPageNumber        = 5000
	userListMaxQueryLength       = 500
	userListQueryTimeout         = 1500 * time.Millisecond
	userListSlowQueryThreshold   = 500 * time.Millisecond
	userListCacheableMaxPageSize = 50
	userListCacheVersion         = "v1"
)

var (
	userListLikeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
)

type userListPagination struct {
	Page      int
	Size      int
	Offset    int
	Limit     int
	sanitized bool
}

func (p userListPagination) isDefault() bool {
	return p.Page == userListDefaultPage && p.Size == userListDefaultPageSize
}

// GET /api/users (public)
func (h *AuthHandler) UserList(c *gin.Context) {
	queryRaw := c.Query("q")
	sanitizedQuery, hasFilter, queryAdjusted := normalizeUserListQuery(queryRaw)
	pagination := parseUserListPagination(c.Query("page"), c.Query("page_size"))

	if queryAdjusted {
		zap.L().Debug("user list query normalized", zap.Int("original_runes", utf8.RuneCountInString(queryRaw)))
	}
	if pagination.sanitized {
		zap.L().Debug("user list pagination normalized", zap.Int("page", pagination.Page), zap.Int("size", pagination.Size))
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), userListQueryTimeout)
	defer cancel()

	shouldCache := h.cache != nil && !hasFilter && pagination.Page == userListDefaultPage && pagination.Size <= userListCacheableMaxPageSize
	cacheKey := ""
	if shouldCache {
		cacheKey = buildUserListCacheKey(sanitizedQuery, pagination.Page, pagination.Size)
		var cached struct {
			Users []map[string]any `json:"users"`
		}
		ok, err := h.readJSONFromCache(ctx, cacheKey, &cached)
		if err != nil {
			zap.L().Warn("failed to read user list cache", zap.Error(err))
		} else if ok {
			basichttp.OK(c, gin.H{"users": cached.Users})
			return
		}
	}

	var users []model.User
	query := h.db.WithContext(ctx).Model(&model.User{}).
		Select("id, username, display_name, avatar_url, is_online, last_heartbeat").
		Where("deleted_at IS NULL").
		Order("username ASC")
	if hasFilter {
		pattern := "%" + sanitizedQuery + "%"
		query = query.Where("(username LIKE ? ESCAPE '\\' OR (display_name IS NOT NULL AND display_name LIKE ? ESCAPE '\\'))", pattern, pattern)
	}

	start := time.Now()
	if err := query.Offset(pagination.Offset).Limit(pagination.Limit).Find(&users).Error; err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			basichttp.Fail(c, http.StatusGatewayTimeout, "TIMEOUT", "query timeout exceeded")
			return
		}
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	duration := time.Since(start)

	// Batch query active tags for all users
	userIDs := make([]string, len(users))
	for i := range users {
		userIDs[i] = users[i].ID
	}
	tagService := service.NewUserTagService(h.db)
	userTags, _ := tagService.GetActiveUserTagsBatch(userIDs)

	result := make([]gin.H, len(users))
	for i := range users {
		u := &users[i]
		var displayName any
		if u.DisplayName != nil {
			displayName = *u.DisplayName
		}
		item := gin.H{
			"id":             u.ID,
			"username":       u.Username,
			"display_name":   displayName,
			"avatar_url":     u.AvatarURL,
			"is_online":      u.IsOnline,
			"last_heartbeat": u.LastHeartbeat,
			"active_tag":     nil,
		}
		if tag, ok := userTags[u.ID]; ok && tag != nil {
			item["active_tag"] = gin.H{
				"id":               tag.ID,
				"name":             tag.Name,
				"title":            tag.Title,
				"background_color": tag.BackgroundColor,
				"text_color":       tag.TextColor,
				"tag_type":         tag.TagType,
				"css_styles":       tag.CssStyles,
			}
		}
		result[i] = item
	}

	if shouldCache {
		payload := struct {
			Users []gin.H `json:"users"`
		}{Users: result}
		if err := h.writeJSONToCache(ctx, cacheKey, payload, h.userListCacheTTL()); err != nil {
			zap.L().Debug("user list cache store failed", zap.Error(err))
		}
	}

	if duration >= userListSlowQueryThreshold {
		zap.L().Info("user list query slow", zap.Duration("duration", duration), zap.Int("count", len(result)), zap.Bool("filter", hasFilter))
	}

	basichttp.OK(c, gin.H{"users": result})
}

func parseUserListPagination(pageRaw, sizeRaw string) userListPagination {
	page := userListDefaultPage
	size := userListDefaultPageSize
	sanitized := false

	if pageRaw = strings.TrimSpace(pageRaw); pageRaw != "" {
		if parsed, err := strconv.Atoi(pageRaw); err == nil && parsed > 0 {
			if parsed > userListMaxPageNumber {
				page = userListMaxPageNumber
				sanitized = true
			} else {
				page = parsed
			}
		} else {
			sanitized = true
		}
	}

	if sizeRaw = strings.TrimSpace(sizeRaw); sizeRaw != "" {
		if parsed, err := strconv.Atoi(sizeRaw); err == nil && parsed > 0 {
			if parsed > userListMaxPageSize {
				size = userListMaxPageSize
				sanitized = true
			} else {
				size = parsed
			}
		} else {
			sanitized = true
		}
	}

	offset := (page - 1) * size

	return userListPagination{
		Page:      page,
		Size:      size,
		Offset:    offset,
		Limit:     size,
		sanitized: sanitized,
	}
}

func normalizeUserListQuery(raw string) (string, bool, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false, false
	}

	runes := []rune(trimmed)
	changed := false
	if len(runes) > userListMaxQueryLength {
		runes = runes[:userListMaxQueryLength]
		changed = true
	}

	filtered := make([]rune, 0, len(runes))
	for _, r := range runes {
		if unicode.IsControl(r) {
			changed = true
			continue
		}
		filtered = append(filtered, r)
	}

	if len(filtered) == 0 {
		return "", false, true
	}

	sanitized := userListLikeEscaper.Replace(string(filtered))
	if sanitized != string(filtered) {
		changed = true
	}

	return sanitized, true, changed
}

func (h *AuthHandler) readJSONFromCache(ctx context.Context, key string, dest any) (bool, error) {
	if h.cache == nil || key == "" {
		return false, nil
	}
	payload, ok, err := h.cache.Get(ctx, key)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(payload, dest); err != nil {
		return false, err
	}
	return true, nil
}

func (h *AuthHandler) writeJSONToCache(ctx context.Context, key string, value any, ttl time.Duration) error {
	if h.cache == nil || key == "" || ttl <= 0 {
		return nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return h.cache.Set(ctx, key, payload, ttl)
}

func (h *AuthHandler) cacheUserPublic(ctx context.Context, user *model.User, payload gin.H) {
	if h.cache == nil || user == nil {
		return
	}
	ttl := h.userCacheTTL()
	if ttl <= 0 {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		zap.L().Warn("marshal user cache payload failed", zap.Error(err))
		return
	}
	keys := []string{userCacheKeyByID(user.ID)}
	if user.Username != "" {
		keys = append(keys, userCacheKeyByUsername(user.Username))
	}
	for _, key := range keys {
		if err := h.cache.Set(ctx, key, data, ttl); err != nil {
			zap.L().Debug("user cache set failed", zap.Error(err))
		}
	}
}

func (h *AuthHandler) invalidateUserCache(ctx context.Context, id string, usernames ...string) {
	invalidateUserCaches(ctx, h.cache, id, usernames...)
}

func (h *AuthHandler) invalidateUserListCache(ctx context.Context) {
	invalidateUserListCaches(ctx, h.cache)
}

func (h *AuthHandler) userCacheTTL() time.Duration {
	if ttl := h.cfg.CacheUserTTL; ttl > 0 {
		return ttl
	}
	return 30 * time.Minute
}

func (h *AuthHandler) userListCacheTTL() time.Duration {
	if ttl := h.cfg.CacheUserListTTL; ttl > 0 {
		return ttl
	}
	return 5 * time.Minute
}

func invalidateUserCaches(ctx context.Context, cache service.Cache, id string, usernames ...string) {
	if cache == nil {
		return
	}
	keySet := make(map[string]struct{})
	if id != "" {
		keySet[userCacheKeyByID(id)] = struct{}{}
	}
	for _, uname := range usernames {
		normalized := strings.TrimSpace(uname)
		if normalized == "" {
			continue
		}
		keySet[userCacheKeyByUsername(normalized)] = struct{}{}
	}
	if len(keySet) > 0 {
		keys := make([]string, 0, len(keySet))
		for k := range keySet {
			keys = append(keys, k)
		}
		if err := cache.Delete(ctx, keys...); err != nil {
			zap.L().Debug("user cache invalidation failed", zap.Error(err))
		}
	}
	invalidateUserListCaches(ctx, cache)
}

func invalidateUserListCaches(ctx context.Context, cache service.Cache) {
	if cache == nil {
		return
	}
	sizeSet := map[int]struct{}{
		userListDefaultPageSize:      {},
		userListCacheableMaxPageSize: {},
	}
	keys := make([]string, 0, len(sizeSet))
	for size := range sizeSet {
		keys = append(keys, buildUserListCacheKey("", userListDefaultPage, size))
	}
	if err := cache.Delete(ctx, keys...); err != nil {
		zap.L().Debug("user list cache invalidation failed", zap.Error(err))
	}
}

func userCacheKeyByID(id string) string {
	return "user:public:v1:id:" + id
}

func userCacheKeyByUsername(username string) string {
	normalized := strings.ToLower(strings.TrimSpace(username))
	sum := sha1.Sum([]byte("uname::" + normalized))
	return "user:public:v1:uname:" + hex.EncodeToString(sum[:])
}

func buildUserListCacheKey(query string, page, size int) string {
	normalized := strings.ToLower(query)
	base := strings.Join([]string{
		userListCacheVersion,
		strconv.Itoa(page),
		strconv.Itoa(size),
		normalized,
	}, ":")
	sum := sha1.Sum([]byte(base))
	return "user:list:" + hex.EncodeToString(sum[:])
}

// GET /api/users/:id/status (public)
// Returns existence and deletion/ban status without 404 for deleted/missing users.
func (h *AuthHandler) GetUserStatusByID(c *gin.Context) {
	id := c.Param("id")

	// Handle AI system user query
	if id == model.AI_SYSTEM_UUID {
		basichttp.OK(c, gin.H{
			"exists":     true,
			"is_deleted": false,
			"is_banned":  false,
		})
		return
	}

	var u model.User
	if err := h.db.Unscoped().First(&u, "id = ?", id).Error; err != nil {
		basichttp.OK(c, gin.H{"exists": false})
		return
	}
	basichttp.OK(c, gin.H{"exists": true, "is_deleted": u.DeletedAt != nil, "is_banned": u.IsBanned})
}

// GET /api/users/by-username/:username/status (public)
func (h *AuthHandler) GetUserStatusByUsername(c *gin.Context) {
	uname := c.Param("username")
	var u model.User
	if err := h.db.Unscoped().Select("id, deleted_at, is_banned").First(&u, "username = ?", uname).Error; err != nil {
		basichttp.OK(c, gin.H{"exists": false})
		return
	}
	basichttp.OK(c, gin.H{"exists": true, "is_deleted": u.DeletedAt != nil, "is_banned": u.IsBanned, "id": u.ID})
}

// GET /api/users/:id/active-tag (public)
// Returns the active tag of a user by ID
func (h *AuthHandler) GetUserActiveTagByID(c *gin.Context) {
	id := c.Param("id")

	// AI system user has no tag
	if id == model.AI_SYSTEM_UUID {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "AI system has no tag")
		return
	}

	var u model.User
	if err := h.db.Unscoped().Select("id", "deleted_at").First(&u, "id = ?", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	svc := service.NewUserTagService(h.db)
	tag, err := svc.GetActiveUserTag(id)
	if err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	if tag == nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "active tag not found")
		return
	}
	basichttp.OK(c, gin.H{
		"name":             tag.Name,
		"title":            tag.Title,
		"background_color": tag.BackgroundColor,
		"text_color":       tag.TextColor,
		"user_deleted":     u.DeletedAt != nil,
	})
}

// GET /api/users/by-username/:username/active-tag (public)
// Returns the active tag of a user by username
func (h *AuthHandler) GetUserActiveTagByUsername(c *gin.Context) {
	uname := c.Param("username")
	var u model.User
	if err := h.db.Unscoped().Select("id", "deleted_at").First(&u, "username = ?", uname).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	svc := service.NewUserTagService(h.db)
	tag, err := svc.GetActiveUserTag(u.ID)
	if err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	if tag == nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "active tag not found")
		return
	}
	basichttp.OK(c, gin.H{
		"name":             tag.Name,
		"title":            tag.Title,
		"background_color": tag.BackgroundColor,
		"text_color":       tag.TextColor,
		"user_deleted":     u.DeletedAt != nil,
	})
}
