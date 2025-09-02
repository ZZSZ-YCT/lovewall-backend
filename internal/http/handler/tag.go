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
	if err := q.Order("created_at DESC").Offset((page-1)*size).Limit(size).Find(&items).Error; err != nil {
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
	basichttp.OK(c, tag)
}

func (h *TagHandler) DeleteTag(c *gin.Context) {
	id := c.Param("id")
	var tag model.Tag
	if err := h.db.First(&tag, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not found")
		return
	}

	// Soft delete
	now := time.Now()
	if err := h.db.Model(&model.Tag{}).Where("id = ?", id).Update("deleted_at", now).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
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
	if err := q.Order("created_at DESC").Offset((page-1)*size).Limit(size).Find(&items).Error; err != nil {
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