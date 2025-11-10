package handler

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"lovewall/internal/config"
	basichttp "lovewall/internal/http"
	mw "lovewall/internal/http/middleware"
	"lovewall/internal/model"
	"lovewall/internal/service"
)

type AdminHandler struct {
	db    *gorm.DB
	cfg   *config.Config
	cache service.Cache
}

func NewAdminHandler(db *gorm.DB, cfg *config.Config, cache service.Cache) *AdminHandler {
	return &AdminHandler{db: db, cfg: cfg, cache: cache}
}

// Only superadmin can overwrite permissions
type permBody struct {
	Permissions []string `json:"permissions" binding:"required"`
}

func (h *AdminHandler) SetUserPermissions(c *gin.Context) {
	if !mw.IsSuper(c, h.db) {
		basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return
	}
	id := c.Param("id")
	// Check if user exists
	var user model.User
	if err := h.db.First(&user, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	if user.IsSuperadmin {
		currentUserID, _ := c.Get(mw.CtxUserID)
		if currentUserID != id {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "cannot modify superadmin data")
			return
		}
	}
	var body permBody
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	// sanitize
	uniq := map[string]struct{}{}
	perms := make([]string, 0, len(body.Permissions))
	for _, p := range body.Permissions {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := uniq[p]; ok {
			continue
		}
		uniq[p] = struct{}{}
		perms = append(perms, p)
	}
	tx := h.db.Begin()
	// Use Unscoped to permanently delete old permissions for this operation
	if err := tx.Unscoped().Where("user_id = ?", id).Delete(&model.UserPermission{}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	for _, p := range perms {
		up := model.UserPermission{UserID: id, Permission: p}
		if err := tx.Create(&up).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
			return
		}
	}
	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "set_user_permissions", "user", id, map[string]any{"permissions": perms})
		}
	}
	invalidateUserCaches(c.Request.Context(), h.cache, id, user.Username)
	basichttp.OK(c, gin.H{"user_id": id, "permissions": perms})
}

// List users (MANAGE_USERS)
func (h *AdminHandler) ListUsers(c *gin.Context) {
	q := strings.TrimSpace(c.Query("q"))
	status := strings.TrimSpace(c.Query("status"))
	page := 1
	size := 20
	if v := c.Query("page"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &page)
	}
	if v := c.Query("page_size"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &size)
		if size > 100 {
			size = 100
		}
	}
	dbq := h.db.Model(&model.User{}).Where("deleted_at IS NULL")
	if q != "" {
		like := "%" + q + "%"
		dbq = dbq.Where("username LIKE ? OR email LIKE ?", like, like)
	}
	if status != "" {
		dbq = dbq.Where("status = ?", status)
	}
	var total int64
	dbq.Count(&total)
	var users []model.User
	if err := dbq.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&users).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	// Fetch permissions for listed users
	idList := make([]string, 0, len(users))
	for i := range users {
		idList = append(idList, users[i].ID)
	}
	permMap := map[string][]string{}
	if len(idList) > 0 {
		var ups []model.UserPermission
		if err := h.db.Where("user_id IN ? AND deleted_at IS NULL", idList).Find(&ups).Error; err == nil {
			for _, up := range ups {
				permMap[up.UserID] = append(permMap[up.UserID], up.Permission)
			}
		}
	}

	// Fetch active tags for listed users
	tagMap := map[string]*model.Tag{}
	if len(idList) > 0 {
		var userTags []model.UserTag
		if err := h.db.Preload("Tag").Where("user_id IN ? AND is_active = ? AND deleted_at IS NULL", idList, true).Find(&userTags).Error; err == nil {
			for _, ut := range userTags {
				tagMap[ut.UserID] = &ut.Tag
			}
		}
	}

	userMap, adminPermMap, err := batchQueryAdminStatus(h.db, idList)
	if err != nil {
		userMap = make(map[string]*model.User)
		adminPermMap = make(map[string]bool)
	}

	items := make([]gin.H, 0, len(users))
	for i := range users {
		userID := users[i].ID
		isAdmin := hasAnyAdminPermissionCached(&users[i], adminPermMap[userID])
		if cachedUser, ok := userMap[userID]; ok {
			isAdmin = hasAnyAdminPermissionCached(cachedUser, adminPermMap[userID])
		}

		entry := sanitizeUserCached(&users[i], isAdmin)
		if perms, ok := permMap[userID]; ok {
			entry["permissions"] = perms
		} else {
			entry["permissions"] = []string{}
		}

		if tag, exists := tagMap[userID]; exists && tag != nil {
			entry["active_tag"] = gin.H{
				"id":               tag.ID,
				"name":             tag.Name,
				"title":            tag.Title,
				"background_color": tag.BackgroundColor,
				"text_color":       tag.TextColor,
			}
		} else {
			entry["active_tag"] = nil
		}

		items = append(items, entry)
	}
	basichttp.OK(c, gin.H{"total": total, "items": items, "page": page, "page_size": size})
}

// PUT /api/admin/users/:id/password (auth; MANAGE_USERS or superadmin)
func (h *AdminHandler) UpdateUserPassword(c *gin.Context) {
	id := c.Param("id")
	// Permission check: superadmin or MANAGE_USERS
	if !mw.IsSuper(c, h.db) {
		uid, _ := c.Get(mw.CtxUserID)
		var cnt int64
		h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL", uid, "MANAGE_USERS").Scan(&cnt)
		if cnt == 0 {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
			return
		}
	}
	var body struct {
		NewPassword string `json:"new_password" binding:"required,min=6,max=64"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	var user model.User
	if err := h.db.First(&user, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	if user.IsSuperadmin {
		currentUserID, _ := c.Get(mw.CtxUserID)
		if currentUserID != id {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "cannot modify superadmin data")
			return
		}
	}
	// Only superadmin can modify another admin's password
	if hasAnyAdminPermission(h.db, id) {
		if !mw.IsSuper(c, h.db) {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "only superadmin can modify admin password")
			return
		}
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "hash password failed")
		return
	}
	if err := h.db.Model(&user).Update("password_hash", string(hashed)).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	// Revoke all sessions for this user after admin password reset
	_ = h.db.Where("user_id = ?", id).Delete(&model.UserSession{}).Error
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "update_user_password", "user", id, nil)
		}
	}
	c.Status(http.StatusNoContent)
}

// POST /api/admin/users/:id/ban (auth; MANAGE_USERS or super)
// Body: {"reason":"string"}
func (h *AdminHandler) BanUser(c *gin.Context) {
	id := c.Param("id")
	// Permission check: superadmin or MANAGE_USERS
	if !mw.IsSuper(c, h.db) {
		uid, _ := c.Get(mw.CtxUserID)
		var cnt int64
		h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL", uid, "MANAGE_USERS").Scan(&cnt)
		if cnt == 0 {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
			return
		}
	}
	var body struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	var user model.User
	if err := h.db.First(&user, "id = ? AND deleted_at IS NULL", id).Error; err == nil {
		if user.IsSuperadmin {
			currentUserID, _ := c.Get(mw.CtxUserID)
			if currentUserID != id {
				basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "cannot modify superadmin data")
				return
			}
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "ban failed")
		return
	}
	now := time.Now()
	updates := map[string]any{"is_banned": true, "ban_reason": body.Reason, "banned_at": now}
	if err := h.db.Model(&model.User{}).Where("id = ? AND deleted_at IS NULL", id).Updates(updates).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "ban failed")
		return
	}
	// Invalidate all active sessions immediately
	_ = h.db.Where("user_id = ?", id).Delete(&model.UserSession{}).Error
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "ban_user", "user", id, map[string]any{"reason": body.Reason})
		}
	}
	invalidateUserCaches(c.Request.Context(), h.cache, id, user.Username)
	basichttp.OK(c, gin.H{"id": id, "is_banned": true, "ban_reason": body.Reason})
}

// POST /api/admin/users/:id/unban (auth; MANAGE_USERS or super)
func (h *AdminHandler) UnbanUser(c *gin.Context) {
	id := c.Param("id")
	if !mw.IsSuper(c, h.db) {
		uid, _ := c.Get(mw.CtxUserID)
		var cnt int64
		h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL", uid, "MANAGE_USERS").Scan(&cnt)
		if cnt == 0 {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
			return
		}
	}
	var user model.User
	if err := h.db.First(&user, "id = ? AND deleted_at IS NULL", id).Error; err == nil {
		if user.IsSuperadmin {
			currentUserID, _ := c.Get(mw.CtxUserID)
			if currentUserID != id {
				basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "cannot modify superadmin data")
				return
			}
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "unban failed")
		return
	}
	updates := map[string]any{"is_banned": false, "ban_reason": nil, "banned_at": nil}
	if err := h.db.Model(&model.User{}).Where("id = ? AND deleted_at IS NULL", id).Updates(updates).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "unban failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "unban_user", "user", id, nil)
		}
	}
	invalidateUserCaches(c.Request.Context(), h.cache, id, user.Username)
	basichttp.OK(c, gin.H{"id": id, "is_banned": false})
}

// DELETE /api/admin/users/:id (auth; superadmin only)
// Soft delete a user to prevent future login while preserving posts/comments and profile display.
// Also revokes all active sessions immediately.
func (h *AdminHandler) DeleteUser(c *gin.Context) {
	if !mw.IsSuper(c, h.db) {
		basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return
	}
	id := c.Param("id")
	// Soft delete user (sets deleted_at)
	var user model.User
	if err := h.db.First(&user, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	if user.IsSuperadmin {
		currentUserID, _ := c.Get(mw.CtxUserID)
		if currentUserID != id {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "cannot modify superadmin data")
			return
		}
	}
	if err := h.db.Delete(&user).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	// Revoke sessions
	_ = h.db.Where("user_id = ?", id).Delete(&model.UserSession{}).Error
	// Log operation
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "delete_user", "user", id, nil)
		}
	}
	invalidateUserCaches(c.Request.Context(), h.cache, id, user.Username)
	basichttp.OK(c, gin.H{"id": id, "deleted": true, "is_deleted": true})
}

// GET /api/admin/metrics/overview (auth; MANAGE_USERS or super)
// Returns totals: platform total comments, today's total comments, today's new users
func (h *AdminHandler) MetricsOverview(c *gin.Context) {
	// Permission: super or MANAGE_USERS
	if !mw.IsSuper(c, h.db) {
		uid, _ := c.Get(mw.CtxUserID)
		var cnt int64
		h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL", uid, "MANAGE_USERS").Scan(&cnt)
		if cnt == 0 {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
			return
		}
	}

	// Compute start of today in server's local time
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	var totalComments, todayComments int64
	var totalUsers, todayNewUsers int64
	var totalPosts, todayNewPosts int64

	// Totals (exclude soft-deleted users/posts; comments are hard-deleted in this codebase)
	h.db.Model(&model.User{}).Where("deleted_at IS NULL").Count(&totalUsers)
	h.db.Model(&model.Post{}).Where("deleted_at IS NULL").Count(&totalPosts)
	h.db.Model(&model.Comment{}).Where("deleted_at IS NULL").Count(&totalComments)

	// Today's new (exclude soft-deleted users/posts)
	h.db.Model(&model.User{}).Where("deleted_at IS NULL AND created_at >= ?", start).Count(&todayNewUsers)
	h.db.Model(&model.Post{}).Where("deleted_at IS NULL AND created_at >= ?", start).Count(&todayNewPosts)
	h.db.Model(&model.Comment{}).Where("deleted_at IS NULL AND created_at >= ?", start).Count(&todayComments)

	basichttp.OK(c, gin.H{
		"since": start,
		// Totals
		"total_users":    totalUsers,
		"total_posts":    totalPosts,
		"total_comments": totalComments,
		// Today's new
		"today_new_users": todayNewUsers,
		"today_new_posts": todayNewPosts,
		"today_comments":  todayComments,
	})
}

// POST /api/admin/posts/:id/approve (auth; MANAGE_POSTS or superadmin)
func (h *AdminHandler) ApprovePost(c *gin.Context) {
	id := c.Param("id")
	// Permission check: allow superadmin or user having the post management permission
	if !mw.IsSuper(c, h.db) {
		uid, _ := c.Get(mw.CtxUserID)
		var cnt int64
		h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL",
			uid, "MANAGE_POSTS").Scan(&cnt)
		if cnt == 0 {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
			return
		}
	}
	updates := map[string]any{"status": 0, "audit_status": 0, "audit_msg": nil, "manual_review_requested": false}
	if err := h.db.Model(&model.Post{}).Where("id = ? AND deleted_at IS NULL", id).Updates(updates).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "approve failed")
		return
	}
	basichttp.OK(c, gin.H{"id": id, "approved": true})
}

// POST /api/admin/posts/:id/reject (auth; MANAGE_POSTS or superadmin)
// Rejects and permanently deletes the post along with its comments and images
func (h *AdminHandler) RejectPost(c *gin.Context) {
	id := c.Param("id")
	if !mw.IsSuper(c, h.db) {
		uid, _ := c.Get(mw.CtxUserID)
		var cnt int64
		h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL",
			uid, "MANAGE_POSTS").Scan(&cnt)
		if cnt == 0 {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
			return
		}
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	// Fetch post to notify author
	var p model.Post
	if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}

	// Hard delete post and related data
	tx := h.db.Begin()
	if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.Comment{}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.PostImage{}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	if err := tx.Unscoped().Delete(&p).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}

	// Notify author
	reason := body.Reason
	if reason == "" {
		reason = "审核未通过"
	}
	service.Notify(h.db, p.AuthorID, "帖子审核未通过", "你的帖子未通过审核已被删除,原因:"+reason, map[string]any{"post_id": p.ID})

	// Log operation
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "reject_post", "post", id, map[string]any{"reason": reason})
		}
	}

	basichttp.OK(c, gin.H{"id": id, "rejected": true, "deleted": true})
}
