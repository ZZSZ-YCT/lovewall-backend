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

type TagHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewTagHandler(db *gorm.DB, cfg *config.Config) *TagHandler {
	return &TagHandler{db: db, cfg: cfg}
}

// Tag CRUD Operations (Admin only)

type CreateTagRequest struct {
	Name            string  `json:"name" binding:"required,min=1,max=50"`
	Title           string  `json:"title" binding:"required,min=1,max=100"`
	BackgroundColor string  `json:"background_color" binding:"required,len=7"` // #RRGGBB
	TextColor       string  `json:"text_color" binding:"required,len=7"`       // #RRGGBB
	Description     *string `json:"description"`
}

func (h *TagHandler) CreateTag(c *gin.Context) {
	var req CreateTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid request")
		return
	}

	// Check name uniqueness
	var count int64
	h.db.Model(&model.Tag{}).Where("name = ? AND deleted_at IS NULL", req.Name).Count(&count)
	if count > 0 {
		basichttp.Fail(c, http.StatusConflict, "CONFLICT", "tag name already exists")
		return
	}

	tag := &model.Tag{
		Name:            req.Name,
		Title:           req.Title,
		BackgroundColor: req.BackgroundColor,
		TextColor:       req.TextColor,
		Description:     req.Description,
		IsActive:        true,
	}

	if err := h.db.Create(tag).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "create failed")
		return
	}
	// Log operation
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "create_tag", "tag", tag.ID, map[string]any{"name": tag.Name})
		}
	}
	basichttp.JSON(c, http.StatusCreated, tag)
}

func (h *TagHandler) ListTags(c *gin.Context) {
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	var items []model.Tag
	q := h.db.Model(&model.Tag{}).Where("deleted_at IS NULL")

	// Filter by active status if specified
	if active := c.Query("active"); active != "" {
		if active == "true" {
			q = q.Where("is_active = ?", true)
		} else if active == "false" {
			q = q.Where("is_active = ?", false)
		}
	}

	q.Count(&total)
	if err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}

	basichttp.OK(c, gin.H{
		"total":     total,
		"items":     items,
		"page":      page,
		"page_size": size,
	})
}

func (h *TagHandler) GetTag(c *gin.Context) {
	id := c.Param("id")
	var tag model.Tag
	if err := h.db.First(&tag, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not found")
		return
	}
	basichttp.OK(c, tag)
}

type UpdateTagRequest struct {
	Title           *string `json:"title"`
	BackgroundColor *string `json:"background_color"`
	TextColor       *string `json:"text_color"`
	Description     *string `json:"description"`
	IsActive        *bool   `json:"is_active"`
}

func (h *TagHandler) UpdateTag(c *gin.Context) {
	id := c.Param("id")
	var req UpdateTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid request")
		return
	}

	var tag model.Tag
	if err := h.db.First(&tag, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not found")
		return
	}

	updates := make(map[string]interface{})
	if req.Title != nil {
		updates["title"] = *req.Title
	}
	if req.BackgroundColor != nil {
		updates["background_color"] = *req.BackgroundColor
	}
	if req.TextColor != nil {
		updates["text_color"] = *req.TextColor
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}

	if len(updates) == 0 {
		basichttp.OK(c, tag)
		return
	}

	if err := h.db.Model(&tag).Updates(updates).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}

	// Reload updated tag
	h.db.First(&tag, "id = ?", id)
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "update_tag", "tag", id, nil)
		}
	}
	basichttp.OK(c, tag)
}

func (h *TagHandler) DeleteTag(c *gin.Context) {
	id := c.Param("id")
	var tag model.Tag
	if err := h.db.First(&tag, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not found")
		return
	}
	// Cascade delete related records in a transaction
	tx := h.db.Begin()
	// 1) Delete only the user_tag entries that reference this tag
	if err := tx.Unscoped().Where("tag_id = ?", id).Delete(&model.UserTag{}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete user tags failed")
		return
	}
	// 2) Delete all redemption codes (used or not) belonging to this tag
	if err := tx.Unscoped().Where("tag_id = ?", id).Delete(&model.RedemptionCode{}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete codes failed")
		return
	}
	// 3) Hard delete the tag itself
	if err := tx.Unscoped().Delete(&tag).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete tag failed")
		return
	}
	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "delete_tag", "tag", id, nil)
		}
	}
	basichttp.OK(c, gin.H{"id": id, "deleted": true})
}

// Redemption Code Management

type GenerateCodesRequest struct {
	TagID     string     `json:"tag_id" binding:"required"`
	Count     int        `json:"count" binding:"required,min=1,max=10000"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (h *TagHandler) GenerateRedemptionCodes(c *gin.Context) {
	var req GenerateCodesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid request")
		return
	}

	// Verify tag exists
	var tag model.Tag
	if err := h.db.First(&tag, "id = ? AND deleted_at IS NULL AND is_active = ?", req.TagID, true).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not found")
		return
	}

	generator := &service.RedemptionCodeGenerator{}
	codes, err := generator.GenerateBatch(req.Count)
	if err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate codes")
		return
	}

	batchID, err := generator.GenerateBatchID()
	if err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate batch ID")
		return
	}

	// Save codes to database in transaction
	tx := h.db.Begin()
	redemptionCodes := make([]model.RedemptionCode, 0, len(codes))

	for _, code := range codes {
		rc := model.RedemptionCode{
			Code:      code,
			TagID:     req.TagID,
			IsUsed:    false,
			ExpiresAt: req.ExpiresAt,
			BatchID:   &batchID,
		}

		if err := tx.Create(&rc).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save codes")
			return
		}
		redemptionCodes = append(redemptionCodes, rc)
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "generate_redemption_codes", "tag", tag.ID, map[string]any{"count": len(codes)})
		}
	}
	basichttp.JSON(c, http.StatusCreated, gin.H{
		"batch_id": batchID,
		"tag":      tag,
		"count":    len(codes),
		"codes":    redemptionCodes,
	})
}

func (h *TagHandler) ListRedemptionCodes(c *gin.Context) {
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	var items []model.RedemptionCode
	q := h.db.Model(&model.RedemptionCode{}).Where("deleted_at IS NULL").Preload("Tag").Preload("User")

	// Filters
	if tagID := c.Query("tag_id"); tagID != "" {
		q = q.Where("tag_id = ?", tagID)
	}
	if code := c.Query("code"); code != "" {
		q = q.Where("code = ?", code)
	}
	if batchID := c.Query("batch_id"); batchID != "" {
		q = q.Where("batch_id = ?", batchID)
	}
	if used := c.Query("used"); used != "" {
		if used == "true" {
			q = q.Where("is_used = ?", true)
		} else if used == "false" {
			q = q.Where("is_used = ?", false)
		}
	}

	q.Count(&total)
	if err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}

	basichttp.OK(c, gin.H{
		"total":     total,
		"items":     items,
		"page":      page,
		"page_size": size,
	})
}

// GET /api/redemption-codes/by-code/:code (auth; MANAGE_TAGS)
// Returns detailed information for a redemption code, including whether it's used and by whom.
func (h *TagHandler) GetRedemptionCodeByCode(c *gin.Context) {
	codeStr := c.Param("code")
	var rc model.RedemptionCode
	if err := h.db.Preload("Tag").Preload("User").First(&rc, "code = ? AND deleted_at IS NULL", codeStr).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "code not found")
		return
	}
	basichttp.OK(c, rc)
}

// POST /api/admin/users/:id/tags/:tag_id (auth; MANAGE_TAGS)
// Assign specified tag to user. If body {"active": true}, set it as active and deactivate others.
func (h *TagHandler) AssignUserTagToUser(c *gin.Context) {
	userID := c.Param("id")
	tagID := c.Param("tag_id")
	var body struct {
		Active bool `json:"active"`
	}
	_ = c.ShouldBindJSON(&body)

	// Ensure tag exists and active state doesn't block assignment
	var tag model.Tag
	if err := h.db.First(&tag, "id = ? AND deleted_at IS NULL", tagID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not found")
		return
	}

	// Use transaction to ensure atomicity
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Check if user already has this tag
	var existing model.UserTag
	err := tx.First(&existing, "user_id = ? AND tag_id = ? AND deleted_at IS NULL", userID, tagID).Error
	if err == nil {
		// Already has tag; update active flag based on body.Active
		if body.Active {
			// Deactivate others and activate this one
			if err := tx.Model(&model.UserTag{}).Where("user_id = ? AND deleted_at IS NULL", userID).Update("is_active", false).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
				return
			}
			if err := tx.Model(&existing).Update("is_active", true).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
				return
			}
		} else {
			// Ensure this tag is not active when body.Active is false
			if err := tx.Model(&existing).Update("is_active", false).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
				return
			}
		}
		if err := tx.Commit().Error; err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
			return
		}
		h.db.Preload("Tag").First(&existing, "id = ?", existing.ID)
		if uid, ok := c.Get(mw.CtxUserID); ok {
			if uidStr, ok2 := uid.(string); ok2 {
				service.LogOperation(h.db, uidStr, "assign_user_tag", "user", userID, map[string]any{"tag_id": tagID, "active": body.Active})
			}
		}
		basichttp.OK(c, existing)
		return
	}

	now := time.Now()
	ut := model.UserTag{
		UserID:     userID,
		TagID:      tagID,
		ObtainedAt: now,
		IsActive:   false,
	}
	if body.Active {
		// Deactivate others and mark this active
		if err := tx.Model(&model.UserTag{}).Where("user_id = ? AND deleted_at IS NULL", userID).Update("is_active", false).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
			return
		}
		ut.IsActive = true
	}
	// Use Select to explicitly set is_active field, even if it's false (zero value)
	if err := tx.Select("ID", "CreatedAt", "UpdatedAt", "UserID", "TagID", "ObtainedAt", "IsActive").Create(&ut).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "create failed")
		return
	}
	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}
	h.db.Preload("Tag").First(&ut, "id = ?", ut.ID)
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "assign_user_tag", "user", userID, map[string]any{"tag_id": tagID, "active": body.Active})
		}
	}
	basichttp.JSON(c, http.StatusCreated, ut)
}

// DELETE /api/admin/users/:id/tags/:tag_id (auth; MANAGE_TAGS)
// Remove specified tag from user (soft delete).
func (h *TagHandler) RemoveUserTagFromUser(c *gin.Context) {
	userID := c.Param("id")
	tagID := c.Param("tag_id")
	var ut model.UserTag
	if err := h.db.First(&ut, "user_id = ? AND tag_id = ? AND deleted_at IS NULL", userID, tagID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user tag not found")
		return
	}
	if err := h.db.Unscoped().Delete(&ut).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "remove_user_tag", "user", userID, map[string]any{"tag_id": tagID})
		}
	}
	basichttp.OK(c, gin.H{"ok": true})
}

// User Redemption

type RedeemCodeRequest struct {
	Code string `json:"code" binding:"required"`
}

func (h *TagHandler) RedeemCode(c *gin.Context) {
	var req RedeemCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid request")
		return
	}

	uid, _ := c.Get(mw.CtxUserID)
	userID := uid.(string)

	// Find the redemption code
	var code model.RedemptionCode
	if err := h.db.Preload("Tag").First(&code, "code = ? AND deleted_at IS NULL", req.Code).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "invalid redemption code")
		return
	}

	// Check if already used
	if code.IsUsed {
		basichttp.Fail(c, http.StatusConflict, "CONFLICT", "redemption code already used")
		return
	}

	// Check expiration
	if code.ExpiresAt != nil && time.Now().After(*code.ExpiresAt) {
		basichttp.Fail(c, http.StatusGone, "EXPIRED", "redemption code has expired")
		return
	}

	// Check if tag is active
	if !code.Tag.IsActive {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag is no longer available")
		return
	}

	// Check if user already has this tag
	var existingUserTag model.UserTag
	err := h.db.First(&existingUserTag, "user_id = ? AND tag_id = ? AND deleted_at IS NULL", userID, code.TagID).Error
	if err == nil {
		basichttp.Fail(c, http.StatusConflict, "CONFLICT", "you already have this tag")
		return
	}

	// Transaction to redeem code
	tx := h.db.Begin()

	// Deactivate all existing user tags to ensure only one active tag
	if err := tx.Model(&model.UserTag{}).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		Update("is_active", false).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "redeem failed")
		return
	}

	// Mark code as used
	now := time.Now()
	if err := tx.Model(&code).Updates(map[string]interface{}{
		"is_used": true,
		"used_by": userID,
		"used_at": now,
	}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "redeem failed")
		return
	}

	// Give user the tag
	userTag := model.UserTag{
		UserID:     userID,
		TagID:      code.TagID,
		ObtainedAt: now,
		IsActive:   true,
	}

	if err := tx.Create(&userTag).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "grant tag failed")
		return
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}

	// Load user tag with relations
	h.db.Preload("Tag").First(&userTag, "id = ?", userTag.ID)

	basichttp.OK(c, gin.H{
		"success":  true,
		"message":  "Tag redeemed successfully",
		"user_tag": userTag,
	})
}

// User Tag Management

func (h *TagHandler) ListUserTags(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	userID := uid.(string)
	// If query all=true, return all tags with status mapping
	if c.Query("all") == "true" {
		svc := service.NewUserTagService(h.db)
		userTags, err := svc.GetUserTags(userID)
		if err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
			return
		}
		items := make([]gin.H, 0, len(userTags))
		for i := range userTags {
			ut := userTags[i]
			status := "inactive"
			if ut.Tag.IsActive {
				if ut.IsActive {
					status = "active"
				} else {
					status = "inactive"
				}
			} else {
				status = "tag_disabled"
			}
			items = append(items, gin.H{
				"user_tag_id": ut.ID,
				"tag": gin.H{
					"id":               ut.Tag.ID,
					"name":             ut.Tag.Name,
					"title":            ut.Tag.Title,
					"background_color": ut.Tag.BackgroundColor,
					"text_color":       ut.Tag.TextColor,
					"is_active":        ut.Tag.IsActive,
				},
				"obtained_at": ut.ObtainedAt,
				"is_active":   ut.IsActive,
				"status":      status,
			})
		}
		basichttp.OK(c, gin.H{"total": len(items), "items": items})
		return
	}

	// Default: keep backward-compatible behavior (only active ones)
	var userTags []model.UserTag
	if err := h.db.Preload("Tag").Where("user_id = ? AND deleted_at IS NULL AND is_active = ?", userID, true).Find(&userTags).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, userTags)
}

func (h *TagHandler) SetActiveTag(c *gin.Context) {
	tagID := c.Param("tag_id")
	uid, _ := c.Get(mw.CtxUserID)
	userID := uid.(string)

	// Verify user has this tag
	var userTag model.UserTag
	if err := h.db.Preload("Tag").First(&userTag, "user_id = ? AND tag_id = ? AND deleted_at IS NULL", userID, tagID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not found")
		return
	}

	// Deactivate all other tags for this user
	h.db.Model(&model.UserTag{}).Where("user_id = ? AND deleted_at IS NULL", userID).Update("is_active", false)

	// Activate this tag
	if err := h.db.Model(&userTag).Update("is_active", true).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}

	basichttp.OK(c, gin.H{
		"message": "Active tag updated successfully",
		"tag":     userTag.Tag,
	})
}

// AdminListUserTags returns all tags owned by the specified user (admin only via router perm).
// GET /api/admin/users/:id/tags (auth; MANAGE_TAGS)
func (h *TagHandler) AdminListUserTags(c *gin.Context) {
	userID := c.Param("id")
	svc := service.NewUserTagService(h.db)
	userTags, err := svc.GetUserTags(userID)
	if err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	items := make([]gin.H, 0, len(userTags))
	for i := range userTags {
		ut := userTags[i]
		status := "inactive"
		if ut.Tag.IsActive {
			if ut.IsActive {
				status = "active"
			} else {
				status = "inactive"
			}
		} else {
			status = "tag_disabled"
		}
		items = append(items, gin.H{
			"user_tag_id": ut.ID,
			"tag": gin.H{
				"id":               ut.Tag.ID,
				"name":             ut.Tag.Name,
				"title":            ut.Tag.Title,
				"background_color": ut.Tag.BackgroundColor,
				"text_color":       ut.Tag.TextColor,
				"is_active":        ut.Tag.IsActive,
			},
			"obtained_at": ut.ObtainedAt,
			"is_active":   ut.IsActive,
			"status":      status,
		})
	}
	basichttp.OK(c, gin.H{"total": len(items), "items": items})
}

// GET /api/my/tags/current-status (auth)
// Returns whether current active tag exists and whether it is enabled (tag.is_active)
func (h *TagHandler) MyCurrentTagStatus(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	userID := uid.(string)
	var ut model.UserTag
	if err := h.db.Preload("Tag").First(&ut, "user_id = ? AND is_active = 1 AND deleted_at IS NULL", userID).Error; err != nil {
		basichttp.OK(c, gin.H{"has_active": false})
		return
	}
	status := "inactive"
	enabled := false
	if ut.Tag.IsActive {
		status = "active"
		enabled = true
	} else {
		status = "tag_disabled"
	}
	basichttp.OK(c, gin.H{
		"has_active":          true,
		"current_tag_enabled": enabled,
		"tag": gin.H{
			"id":        ut.Tag.ID,
			"name":      ut.Tag.Name,
			"title":     ut.Tag.Title,
			"is_active": ut.Tag.IsActive,
		},
		"status": status,
	})
}

// GET /api/my/tags/:tag_id/status (auth)
// Returns whether the specified owned tag is currently enabled (tag.is_active). 404 if user does not own.
func (h *TagHandler) MyTagStatusByTagID(c *gin.Context) {
	tagID := c.Param("tag_id")
	uid, _ := c.Get(mw.CtxUserID)
	userID := uid.(string)
	var ut model.UserTag
	if err := h.db.Preload("Tag").First(&ut, "user_id = ? AND tag_id = ? AND deleted_at IS NULL", userID, tagID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not owned by user")
		return
	}
	enabled := ut.Tag.IsActive
	status := "inactive"
	if enabled {
		status = "active"
	} else {
		status = "tag_disabled"
	}
	basichttp.OK(c, gin.H{
		"tag": gin.H{
			"id":        ut.Tag.ID,
			"name":      ut.Tag.Name,
			"title":     ut.Tag.Title,
			"is_active": ut.Tag.IsActive,
		},
		"enabled": enabled,
		"status":  status,
	})
}

// DELETE /api/redemption-codes (auth; MANAGE_TAGS)
// Body: { "ids": ["id1","id2"], "codes": ["CODE-...", ...] }
// Deletes only unused codes. Used codes are skipped and reported.
func (h *TagHandler) DeleteRedemptionCodes(c *gin.Context) {
	var body struct {
		IDs   []string `json:"ids"`
		Codes []string `json:"codes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || (len(body.IDs) == 0 && len(body.Codes) == 0) {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "provide ids or codes")
		return
	}
	// Fetch matching codes
	dbq := h.db.Model(&model.RedemptionCode{}).Where("deleted_at IS NULL")
	if len(body.IDs) > 0 && len(body.Codes) > 0 {
		dbq = dbq.Where("id IN ? OR code IN ?", body.IDs, body.Codes)
	} else if len(body.IDs) > 0 {
		dbq = dbq.Where("id IN ?", body.IDs)
	} else {
		dbq = dbq.Where("code IN ?", body.Codes)
	}
	var list []model.RedemptionCode
	if err := dbq.Find(&list).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	deletableIDs := make([]string, 0)
	skipped := make([]gin.H, 0)
	foundIDs := make(map[string]struct{})
	for _, rc := range list {
		foundIDs[rc.ID] = struct{}{}
		if rc.IsUsed {
			skipped = append(skipped, gin.H{"id": rc.ID, "code": rc.Code, "reason": "already used"})
			continue
		}
		deletableIDs = append(deletableIDs, rc.ID)
	}
	// Identify requested but not found
	if len(body.IDs) > 0 {
		for _, id := range body.IDs {
			if _, ok := foundIDs[id]; !ok {
				skipped = append(skipped, gin.H{"id": id, "reason": "not found"})
			}
		}
	}
	// Perform delete
	deleted := int64(0)
	if len(deletableIDs) > 0 {
		if err := h.db.Unscoped().Where("id IN ?", deletableIDs).Delete(&model.RedemptionCode{}).Error; err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
			return
		}
		deleted = int64(len(deletableIDs))
	}
	// Log operation
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "delete_redemption_codes", "redemption_code", "", map[string]any{"deleted": deleted, "skipped": len(skipped)})
		}
	}
	basichttp.OK(c, gin.H{"deleted": deleted, "skipped": skipped})
}
