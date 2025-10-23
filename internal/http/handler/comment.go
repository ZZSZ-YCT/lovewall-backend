package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lovewall/internal/config"
	basichttp "lovewall/internal/http"
	mw "lovewall/internal/http/middleware"
	"lovewall/internal/model"
	"lovewall/internal/service"
)

type CommentHandler struct {
	db         *gorm.DB
	cfg        *config.Config
	tagService *service.UserTagService
}

func NewCommentHandler(db *gorm.DB, cfg *config.Config) *CommentHandler {
	return &CommentHandler{
		db:         db,
		cfg:        cfg,
		tagService: service.NewUserTagService(db),
	}
}

// GET /api/posts/:id/comments (public)
func (h *CommentHandler) ListForPost(c *gin.Context) {
	postID := c.Param("id")
	// Ensure post is visible
	var post model.Post
	if err := h.db.First(&post, "id = ? AND deleted_at IS NULL AND status = 0", postID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	var items []model.Comment
	q := h.db.Model(&model.Comment{}).Where("post_id = ? AND deleted_at IS NULL AND status = 0", postID)
	q.Count(&total)
	if err := q.Order("created_at ASC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": h.enrichCommentsWithUserTags(items), "page": page, "page_size": size})
}

// enrichCommentWithUserTag adds user tag information to comment response
func (h *CommentHandler) enrichCommentWithUserTag(comment *model.Comment) gin.H {
	result := gin.H{
		"id":                comment.ID,
		"post_id":           comment.PostID,
		"user_id":           comment.UserID,
		"user_username":     nil,
		"content":           comment.Content,
		"status":            comment.Status,
		"metadata":          comment.Metadata,
		"created_at":        comment.CreatedAt,
		"updated_at":        comment.UpdatedAt,
		"user_tag":          nil,
		"user_display_name": nil,
		"is_user_admin":     false,
	}

	// Get user's active tag
	if tag, err := h.tagService.GetActiveUserTag(comment.UserID); err == nil && tag != nil {
		result["user_tag"] = gin.H{
			"name":             tag.Name,
			"title":            tag.Title,
			"background_color": tag.BackgroundColor,
			"text_color":       tag.TextColor,
		}
	}

	// Attach user's current display name (fallback to username if empty) and admin status
	var user model.User
	if err := h.db.Unscoped().Select("id, username, display_name, is_superadmin").First(&user, "id = ?", comment.UserID).Error; err == nil {
		result["user_username"] = user.Username
		if user.DisplayName != nil && *user.DisplayName != "" {
			result["user_display_name"] = *user.DisplayName
		} else {
			result["user_display_name"] = user.Username
		}
		// Check admin permission
		if user.IsSuperadmin {
			result["is_user_admin"] = true
		} else {
			var cnt int64
			h.db.Model(&model.UserPermission{}).Where("user_id = ? AND deleted_at IS NULL", user.ID).Count(&cnt)
			result["is_user_admin"] = cnt > 0
		}
	}

	return result
}

// enrichCommentsWithUserTags adds user tag information to multiple comments
func (h *CommentHandler) enrichCommentsWithUserTags(comments []model.Comment) []gin.H {
	result := make([]gin.H, 0, len(comments))
	for i := range comments {
		result = append(result, h.enrichCommentWithUserTag(&comments[i]))
	}
	return result
}

type createCommentBody struct {
	Content string `json:"content" binding:"required"`
}

// POST /api/posts/:id/comments (auth)
func (h *CommentHandler) Create(c *gin.Context) {
	postID := c.Param("id")
	// Ensure post is visible for commenting
	var post model.Post
	if err := h.db.First(&post, "id = ? AND deleted_at IS NULL AND status = 0", postID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	var body createCommentBody
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	if len([]rune(body.Content)) > 1000 {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "评论长度超过1000字")
		return
	}
	// Length validation
	if len([]rune(body.Content)) > h.cfg.MaxCommentChars {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "评论长度超过限制")
		return
	}
	uid, _ := c.Get(mw.CtxUserID)
	cm := &model.Comment{
		PostID:      postID,
		UserID:      uid.(string),
		Content:     body.Content,
		Status:      1, // hidden pending moderation
		AuditStatus: 1,
	}
	if err := h.db.Create(cm).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "create failed")
		return
	}
	// Do not increment comment_count yet; will increment when moderation approves
	// Log submission
	if uidStr, ok2 := uid.(string); ok2 {
		service.LogSubmission(h.db, uidStr, "comment_create", "comment", cm.ID, map[string]any{"post_id": cm.PostID, "ip": c.ClientIP()})
	}
	// enqueue async moderation
	service.EnqueueCommentModeration(cm.ID)
	basichttp.JSON(c, http.StatusCreated, cm)
}

// DELETE /api/comments/:id (author or MANAGE_COMMENTS)
func (h *CommentHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	var cm model.Comment
	if err := h.db.First(&cm, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "comment not found")
		return
	}
	uid, _ := c.Get(mw.CtxUserID)
	if uid != cm.UserID {
		if !mw.IsSuper(c) {
			var cnt int64
			h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL", uid, "MANAGE_COMMENTS").Scan(&cnt)
			if cnt == 0 {
				basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
				return
			}
		}
	}
	// Hard delete
	if err := h.db.Unscoped().Delete(&cm).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	// Decrement post comment count only if it had been visible
	if cm.Status == 0 {
		_ = h.db.Model(&model.Post{}).Where("id = ?", cm.PostID).Update("comment_count", gorm.Expr("comment_count - 1")).Error
	}
	basichttp.OK(c, gin.H{"id": id, "deleted": true})
}

// PUT /api/comments/:id (author within 15m or MANAGE_COMMENTS/super)
func (h *CommentHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var cm model.Comment
	if err := h.db.First(&cm, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "comment not found")
		return
	}
	uid, _ := c.Get(mw.CtxUserID)
	if uid != cm.UserID {
		if !mw.IsSuper(c) {
			var cnt int64
			h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL", uid, "MANAGE_COMMENTS").Scan(&cnt)
			if cnt == 0 {
				basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
				return
			}
		}
	} else {
		// author time window
		if time.Since(cm.CreatedAt) > 15*time.Minute {
			// need MANAGE_COMMENTS unless super
			if !mw.IsSuper(c) {
				var cnt int64
				h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL", uid, "MANAGE_COMMENTS").Scan(&cnt)
				if cnt == 0 {
					basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "edit window closed")
					return
				}
			}
		}
	}
	var body struct {
		Content *string `json:"content" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Content == nil || *body.Content == "" {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	if len([]rune(*body.Content)) > 1000 {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "评论长度超过1000字")
		return
	}
	if len([]rune(*body.Content)) > h.cfg.MaxCommentChars {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "评论长度超过限制")
		return
	}
	// set pending moderation again; if previously visible, decrement post comment_count
	wasVisible := (cm.Status == 0)
	if err := h.db.Model(&model.Comment{}).Where("id = ?", id).Updates(map[string]any{"content": *body.Content, "status": 1, "audit_status": 1, "audit_msg": nil}).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	if wasVisible {
		_ = h.db.Model(&model.Post{}).Where("id = ?", cm.PostID).Update("comment_count", gorm.Expr("comment_count - 1")).Error
	}
	// enqueue moderation
	service.EnqueueCommentModeration(id)
	// Log operation if edited by non-author (admin/moderator)
	if uidStr, ok := (func() (string, bool) {
		v, ok := c.Get(mw.CtxUserID)
		if !ok {
			return "", false
		}
		s, ok2 := v.(string)
		return s, ok2
	})(); ok && uidStr != cm.UserID {
		service.LogOperation(h.db, uidStr, "edit_comment", "comment", id, nil)
	}
	if err := h.db.First(&cm, "id = ?", id).Error; err == nil {
		basichttp.OK(c, cm)
	} else {
		basichttp.OK(c, gin.H{"ok": true})
	}
}

// POST /api/comments/:id/hide (MANAGE_COMMENTS) body: {"hide": true}
func (h *CommentHandler) Hide(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Hide bool `json:"hide"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	newStatus := 0
	if body.Hide {
		newStatus = 1
	}
	if err := h.db.Model(&model.Comment{}).Where("id = ? AND deleted_at IS NULL", id).Update("status", newStatus).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			action := "unhide_comment"
			if body.Hide {
				action = "hide_comment"
			}
			service.LogOperation(h.db, uidStr, action, "comment", id, nil)
		}
	}
	basichttp.OK(c, gin.H{"id": id, "status": newStatus})
}

// GET /api/my/comments (auth)
func (h *CommentHandler) ListMine(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}
	var total int64
	var items []model.Comment
	// Only show comments whose posts are visible (posts.status = 0) and not soft-deleted
	q := h.db.Model(&model.Comment{}).
		Joins("JOIN posts ON posts.id = comments.post_id AND posts.deleted_at IS NULL AND posts.status = 0").
		Where("comments.user_id = ? AND comments.deleted_at IS NULL", uid)
	q.Count(&total)
	if err := q.Order("comments.created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": h.enrichCommentsWithUserTags(items), "page": page, "page_size": size})
}

// GET /api/comments (MANAGE_COMMENTS) moderation list
// query: post_id, user_id, status (0/1), page, page_size
func (h *CommentHandler) ListModeration(c *gin.Context) {
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}
	// Exclude comments of posts that are soft-deleted (posts.status = 2),
	// but allow comments for hidden posts (status = 1).
	dbq := h.db.Model(&model.Comment{}).
		Joins("JOIN posts ON posts.id = comments.post_id AND posts.deleted_at IS NULL").
		Where("comments.deleted_at IS NULL AND (posts.status IS NULL OR posts.status <> 2)")
	if v := c.Query("post_id"); v != "" {
		dbq = dbq.Where("comments.post_id = ?", v)
	}
	if v := c.Query("user_id"); v != "" {
		dbq = dbq.Where("comments.user_id = ?", v)
	}
	if v := c.Query("status"); v != "" {
		dbq = dbq.Where("comments.status = ?", v)
	}
	var total int64
	dbq.Count(&total)
	var items []model.Comment
	// Qualify column to avoid ambiguity with JOINed posts table
	if err := dbq.Order("comments.created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": h.enrichCommentsWithUserTags(items), "page": page, "page_size": size})
}
