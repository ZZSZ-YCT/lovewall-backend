package handler

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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

const tagTitleMaxWeight = 12

const (
	tagTypeCollective = "collective"
	tagTypePersonal   = "personal"
)

// CSS安全关键字黑名单（不包括 @keyframes，允许动画）
var disallowedCSSKeywords = []string{
	"@import",     // 禁止外部资源导入
	"expression(", // 禁止 IE 的 expression
	"javascript:", // 禁止 javascript: 协议
	"<script",     // 禁止内联脚本
	"onerror",     // 禁止事件处理
	"onload",      // 禁止事件处理
}

var hexColorRegex = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

func NewTagHandler(db *gorm.DB, cfg *config.Config) *TagHandler {
	return &TagHandler{db: db, cfg: cfg}
}

// Tag CRUD Operations (Admin only)

type CreateTagRequest struct {
	Name            string  `json:"name" binding:"required,min=1,max=50"`
	Title           string  `json:"title" binding:"required,min=1,max=100"`
	BackgroundColor string  `json:"background_color"` // #RRGGBB
	TextColor       string  `json:"text_color"`       // #RRGGBB
	Description     *string `json:"description"`
	TagType         string  `json:"tagType"`
	CssStyles       *string `json:"cssStyles"`
}

func (h *TagHandler) CreateTag(c *gin.Context) {
	var req CreateTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid request")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Title = strings.TrimSpace(req.Title)
	req.BackgroundColor = strings.TrimSpace(req.BackgroundColor)
	req.TextColor = strings.TrimSpace(req.TextColor)
	if req.Name == "" || req.Title == "" {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "name and title are required")
		return
	}
	if !validateTagTitle(req.Title) {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "title must be within 6 Chinese characters or 12 English letters")
		return
	}
	req.TagType = normalizeTagType(req.TagType)
	if !isValidTagType(req.TagType) {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "tagType 仅支持 collective 或 personal")
		return
	}

	var cssValue string
	if req.CssStyles != nil {
		cssValue = strings.TrimSpace(*req.CssStyles)
	}
	hasCss := req.CssStyles != nil && cssValue != ""
	hasColors := req.BackgroundColor != "" || req.TextColor != ""

	if hasCss && hasColors {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "cssStyles 和颜色字段(background_color/text_color)互斥，只能提供其中一种")
		return
	}
	if !hasCss && !hasColors {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "必须提供 cssStyles 或颜色字段(background_color/text_color)其中一种")
		return
	}

	if hasColors {
		if req.BackgroundColor == "" || !hexColorRegex.MatchString(req.BackgroundColor) {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "background_color 格式错误，应为 #RRGGBB")
			return
		}
		if req.TextColor == "" || !hexColorRegex.MatchString(req.TextColor) {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "text_color 格式错误，应为 #RRGGBB")
			return
		}
	}

	var cssPtr *string
	if hasCss {
		if err := validateCSSStyles(cssValue); err != nil {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", err.Error())
			return
		}
		cssCopy := cssValue
		cssPtr = &cssCopy
		req.BackgroundColor = ""
		req.TextColor = ""
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
		TagType:         req.TagType,
		CssStyles:       cssPtr,
	}

	if err := h.db.Create(tag).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "create failed")
		return
	}
	tag.TagType = sanitizeTagType(tag.TagType)
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
	// 只显示集体 Tag，个人 Tag 不在公开列表中展示
	// 使用与其他查询一致的逻辑：LOWER(COALESCE(NULLIF(tag_type, ''), 'collective'))
	q := h.db.Model(&model.Tag{}).Where("deleted_at IS NULL").
		Where("LOWER(COALESCE(NULLIF(tag_type, ''), ?)) = ?", tagTypeCollective, tagTypeCollective)

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

	for i := range items {
		items[i].TagType = sanitizeTagType(items[i].TagType)
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
	tag.TagType = sanitizeTagType(tag.TagType)
	basichttp.OK(c, tag)
}

type UpdateTagRequest struct {
	Title           *string `json:"title"`
	BackgroundColor *string `json:"background_color"`
	TextColor       *string `json:"text_color"`
	Description     *string `json:"description"`
	IsActive        *bool   `json:"is_active"`
	TagType         *string `json:"tagType"`
	CssStyles       *string `json:"cssStyles"`
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

	var cssValue string
	if req.CssStyles != nil {
		cssValue = strings.TrimSpace(*req.CssStyles)
	}
	var bgValue string
	if req.BackgroundColor != nil {
		bgValue = strings.TrimSpace(*req.BackgroundColor)
	}
	var textValue string
	if req.TextColor != nil {
		textValue = strings.TrimSpace(*req.TextColor)
	}

	hasCss := req.CssStyles != nil && cssValue != ""
	hasColors := (req.BackgroundColor != nil && bgValue != "") || (req.TextColor != nil && textValue != "")

	if hasCss && hasColors {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "cssStyles 和颜色字段互斥，只能更新其中一种")
		return
	}

	updates := make(map[string]interface{})
	if req.Title != nil {
		title := strings.TrimSpace(*req.Title)
		if title == "" {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "title cannot be empty")
			return
		}
		if !validateTagTitle(title) {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "title must be within 6 Chinese characters or 12 English letters")
			return
		}
		updates["title"] = title
	}
	if req.BackgroundColor != nil {
		if bgValue != "" && !hexColorRegex.MatchString(bgValue) {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "background_color 格式错误，应为 #RRGGBB")
			return
		}
		updates["background_color"] = bgValue
	}
	if req.TextColor != nil {
		if textValue != "" && !hexColorRegex.MatchString(textValue) {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "text_color 格式错误，应为 #RRGGBB")
			return
		}
		updates["text_color"] = textValue
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.TagType != nil {
		tagType := normalizeTagType(*req.TagType)
		if !isValidTagType(tagType) {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "tagType 仅支持 collective 或 personal")
			return
		}
		updates["tag_type"] = tagType
	}
	if req.CssStyles != nil {
		if cssValue == "" {
			updates["css_styles"] = gorm.Expr("NULL")
		} else {
			if err := validateCSSStyles(cssValue); err != nil {
				basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", err.Error())
				return
			}
			updates["css_styles"] = cssValue
		}
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}

	if hasCss {
		updates["background_color"] = ""
		updates["text_color"] = ""
	}
	if hasColors && req.CssStyles == nil {
		updates["css_styles"] = gorm.Expr("NULL")
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
	tag.TagType = sanitizeTagType(tag.TagType)
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
		redemptionCodes = append(redemptionCodes, model.RedemptionCode{
			Code:      code,
			TagID:     req.TagID,
			IsUsed:    false,
			ExpiresAt: req.ExpiresAt,
			BatchID:   &batchID,
		})
	}

	if err := tx.CreateInBatches(&redemptionCodes, 100).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save codes")
		return
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
// Assign specified tag to user. Body supports {"active": true, "force": true} to bypass activation limits.
func (h *TagHandler) AssignUserTagToUser(c *gin.Context) {
	userID := c.Param("id")
	tagID := c.Param("tag_id")
	var body struct {
		Active bool `json:"active"`
		Force  bool `json:"force"`
	}
	_ = c.ShouldBindJSON(&body)

	// Ensure tag exists and active state doesn't block assignment
	var tag model.Tag
	if err := h.db.First(&tag, "id = ? AND deleted_at IS NULL", tagID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not found")
		return
	}
	tagType := sanitizeTagType(tag.TagType)

	// Use transaction to ensure atomicity
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Check if user already has this tag
	var existing model.UserTag
	err := tx.Preload("Tag").First(&existing, "user_id = ? AND tag_id = ? AND deleted_at IS NULL", userID, tagID).Error
	if err == nil {
		// Already has tag; update active flag based on body.Active
		if body.Active {
			if !existing.IsActive {
				if !body.Force {
					limit := activationLimitForType(tagType)
					count, err := h.countActiveTagsByType(tx, userID, tagType, existing.TagID)
					if err != nil {
						tx.Rollback()
						basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
						return
					}
					if count >= int64(limit) {
						tx.Rollback()
						basichttp.Fail(c, http.StatusBadRequest, "LIMIT_EXCEEDED", "已达到该类型Tag的激活上限")
						return
					}
				}
				if err := tx.Model(&existing).Update("is_active", true).Error; err != nil {
					tx.Rollback()
					basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
					return
				}
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
		existing.Tag.TagType = sanitizeTagType(existing.Tag.TagType)
		if uid, ok := c.Get(mw.CtxUserID); ok {
			if uidStr, ok2 := uid.(string); ok2 {
				service.LogOperation(h.db, uidStr, "assign_user_tag", "user", userID, map[string]any{"tag_id": tagID, "active": body.Active, "force": body.Force})
			}
		}
		basichttp.OK(c, existing)
		return
	}

	if err != nil && err != gorm.ErrRecordNotFound {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
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
		if !body.Force {
			limit := activationLimitForType(tagType)
			count, err := h.countActiveTagsByType(tx, userID, tagType, "")
			if err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
				return
			}
			if count >= int64(limit) {
				tx.Rollback()
				basichttp.Fail(c, http.StatusBadRequest, "LIMIT_EXCEEDED", "已达到该类型Tag的激活上限")
				return
			}
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
	ut.Tag.TagType = sanitizeTagType(ut.Tag.TagType)
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "assign_user_tag", "user", userID, map[string]any{"tag_id": tagID, "active": body.Active, "force": body.Force})
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
	if err := h.db.Preload("Tag").First(&ut, "user_id = ? AND tag_id = ? AND deleted_at IS NULL", userID, tagID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user tag not found")
		return
	}

	// 记录 tag 类型用于后续检查
	tagType := sanitizeTagType(ut.Tag.TagType)

	if err := h.db.Unscoped().Delete(&ut).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}

	// 如果是个人 Tag，检查是否还有其他用户拥有该 Tag
	if tagType == tagTypePersonal {
		var remainingCount int64
		if err := h.db.Model(&model.UserTag{}).Where("tag_id = ? AND deleted_at IS NULL", tagID).Count(&remainingCount).Error; err != nil {
			// 查询失败，记录错误但不阻塞主流程
			if uid, ok := c.Get(mw.CtxUserID); ok {
				if uidStr, ok2 := uid.(string); ok2 {
					service.LogOperation(h.db, uidStr, "auto_delete_personal_tag_failed", "tag", tagID, map[string]any{"reason": "count_error", "error": err.Error()})
				}
			}
		} else if remainingCount == 0 {
			// 如果没有任何用户拥有该 Tag，自动删除 Tag 本身
			if err := h.db.Delete(&model.Tag{}, "id = ?", tagID).Error; err != nil {
				// 删除失败，记录错误
				if uid, ok := c.Get(mw.CtxUserID); ok {
					if uidStr, ok2 := uid.(string); ok2 {
						service.LogOperation(h.db, uidStr, "auto_delete_personal_tag_failed", "tag", tagID, map[string]any{"reason": "delete_error", "error": err.Error()})
					}
				}
			} else {
				// 删除成功，记录操作
				if uid, ok := c.Get(mw.CtxUserID); ok {
					if uidStr, ok2 := uid.(string); ok2 {
						service.LogOperation(h.db, uidStr, "auto_delete_personal_tag", "tag", tagID, map[string]any{"reason": "no_users"})
					}
				}
			}
		}
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

	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	var code model.RedemptionCode
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Preload("Tag").
		First(&code, "code = ? AND deleted_at IS NULL", req.Code).Error; err != nil {
		tx.Rollback()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "invalid redemption code")
			return
		}
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}

	if code.IsUsed {
		tx.Rollback()
		basichttp.Fail(c, http.StatusConflict, "CONFLICT", "redemption code already used")
		return
	}
	if code.ExpiresAt != nil && time.Now().After(*code.ExpiresAt) {
		tx.Rollback()
		basichttp.Fail(c, http.StatusGone, "EXPIRED", "redemption code has expired")
		return
	}
	if !code.Tag.IsActive {
		tx.Rollback()
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag is no longer available")
		return
	}

	var existingUserTag model.UserTag
	if err := tx.First(&existingUserTag, "user_id = ? AND tag_id = ? AND deleted_at IS NULL", userID, code.TagID).Error; err == nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusConflict, "CONFLICT", "you already have this tag")
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "redeem failed")
		return
	}

	tagType := sanitizeTagType(code.Tag.TagType)
	limit := activationLimitForType(tagType)
	activeCount, err := h.countActiveTagsByType(tx, userID, tagType, "")
	if err != nil {
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
		IsActive:   activeCount < int64(limit),
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
	userTag.Tag.TagType = sanitizeTagType(userTag.Tag.TagType)

	message := "Tag redeemed successfully"
	if !userTag.IsActive {
		message = "兑换成功，已添加但需手动激活"
	}

	basichttp.OK(c, gin.H{
		"success":   true,
		"message":   message,
		"user_tag":  userTag,
		"activated": userTag.IsActive,
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
					"tag_type":         sanitizeTagType(ut.Tag.TagType),
					"css_styles":       ut.Tag.CssStyles,
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
	for i := range userTags {
		userTags[i].Tag.TagType = sanitizeTagType(userTags[i].Tag.TagType)
	}
	basichttp.OK(c, userTags)
}

// GetMyActiveTags returns active tags grouped by type for the current user.
func (h *TagHandler) GetMyActiveTags(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	userID := uid.(string)

	var userTags []model.UserTag
	if err := h.db.Preload("Tag").
		Joins("JOIN tags ON tags.id = user_tags.tag_id").
		Where("user_tags.user_id = ? AND user_tags.deleted_at IS NULL AND user_tags.is_active = ?", userID, true).
		Where("tags.deleted_at IS NULL").
		Find(&userTags).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}

	personal := make([]model.Tag, 0)
	collective := make([]model.Tag, 0)

	for i := range userTags {
		tag := userTags[i].Tag
		tag.TagType = sanitizeTagType(tag.TagType)
		if tag.TagType == tagTypePersonal {
			personal = append(personal, tag)
		} else {
			collective = append(collective, tag)
		}
	}

	basichttp.OK(c, gin.H{
		"personal":   personal,
		"collective": collective,
	})
}

func (h *TagHandler) SetActiveTag(c *gin.Context) {
	tagID := c.Param("tag_id")
	uid, _ := c.Get(mw.CtxUserID)
	userID := uid.(string)

	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	var userTag model.UserTag
	if err := tx.Preload("Tag").First(&userTag, "user_id = ? AND tag_id = ? AND deleted_at IS NULL", userID, tagID).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not found")
		return
	}

	if userTag.IsActive {
		if err := tx.Commit().Error; err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
			return
		}
		userTag.Tag.TagType = sanitizeTagType(userTag.Tag.TagType)
		basichttp.OK(c, gin.H{
			"message": "Tag 已激活",
			"tag":     userTag.Tag,
		})
		return
	}

	autoDeactivated := false
	var autoDeactivatedTagID string
	var autoDeactivatedUserTagID string
	tagType := sanitizeTagType(userTag.Tag.TagType)
	limit := activationLimitForType(tagType)
	activeCount, err := h.countActiveTagsByType(tx, userID, tagType, "")
	if err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	if activeCount >= int64(limit) {
		var oldestUserTag model.UserTag
		err := tx.Joins("JOIN tags ON tags.id = user_tags.tag_id").
			Where("user_tags.user_id = ? AND user_tags.is_active = ? AND user_tags.tag_id <> ?", userID, true, tagID).
			Where("user_tags.deleted_at IS NULL").
			Where("tags.deleted_at IS NULL").
			Where("LOWER(COALESCE(NULLIF(tags.tag_type, ''), ?)) = ?", tagTypeCollective, tagType).
			Order("user_tags.obtained_at ASC").
			First(&oldestUserTag).Error
		if err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to find oldest tag")
			return
		}
		if err := tx.Model(&model.UserTag{}).Where("id = ?", oldestUserTag.ID).Update("is_active", false).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to deactivate oldest tag")
			return
		}
		autoDeactivated = true
		autoDeactivatedTagID = oldestUserTag.TagID
		autoDeactivatedUserTagID = oldestUserTag.ID
	}

	if err := tx.Model(&model.UserTag{}).Where("id = ?", userTag.ID).Update("is_active", true).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}

	h.db.Preload("Tag").First(&userTag, "id = ?", userTag.ID)
	userTag.Tag.TagType = sanitizeTagType(userTag.Tag.TagType)

	if autoDeactivated {
		service.LogOperation(h.db, userID, "auto_deactivate_tag", "user_tag", autoDeactivatedUserTagID, map[string]any{"tag_id": autoDeactivatedTagID})
	}

	response := gin.H{
		"message": "Tag 已激活",
		"tag":     userTag.Tag,
	}
	if autoDeactivated {
		response["auto_deactivated_tag_id"] = autoDeactivatedTagID
	}

	basichttp.OK(c, response)
}

// DeactivateTag allows the current user to deactivate a specific tag manually.
func (h *TagHandler) DeactivateTag(c *gin.Context) {
	tagID := c.Param("tag_id")
	uid, _ := c.Get(mw.CtxUserID)
	userID := uid.(string)

	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	var userTag model.UserTag
	if err := tx.Preload("Tag").First(&userTag, "user_id = ? AND tag_id = ? AND deleted_at IS NULL", userID, tagID).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "tag not found")
		return
	}

	if !userTag.IsActive {
		if err := tx.Commit().Error; err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
			return
		}
		userTag.Tag.TagType = sanitizeTagType(userTag.Tag.TagType)
		basichttp.OK(c, gin.H{
			"message": "Tag 已处于未激活状态",
			"tag":     userTag.Tag,
		})
		return
	}

	if err := tx.Model(&userTag).Update("is_active", false).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}

	h.db.Preload("Tag").First(&userTag, "id = ?", userTag.ID)
	userTag.Tag.TagType = sanitizeTagType(userTag.Tag.TagType)

	basichttp.OK(c, gin.H{
		"message": "Tag 已取消激活",
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
				"tag_type":         sanitizeTagType(ut.Tag.TagType),
				"css_styles":       ut.Tag.CssStyles,
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
			"id":         ut.Tag.ID,
			"name":       ut.Tag.Name,
			"title":      ut.Tag.Title,
			"is_active":  ut.Tag.IsActive,
			"tag_type":   sanitizeTagType(ut.Tag.TagType),
			"css_styles": ut.Tag.CssStyles,
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
			"id":         ut.Tag.ID,
			"name":       ut.Tag.Name,
			"title":      ut.Tag.Title,
			"is_active":  ut.Tag.IsActive,
			"tag_type":   sanitizeTagType(ut.Tag.TagType),
			"css_styles": ut.Tag.CssStyles,
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

func normalizeTagType(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return tagTypeCollective
	}
	return value
}

func sanitizeTagType(value string) string {
	value = normalizeTagType(value)
	if !isValidTagType(value) {
		return tagTypeCollective
	}
	return value
}

func isValidTagType(value string) bool {
	switch value {
	case tagTypeCollective, tagTypePersonal:
		return true
	default:
		return false
	}
}

func activationLimitForType(tagType string) int {
	switch sanitizeTagType(tagType) {
	case tagTypePersonal:
		return 2
	default:
		return 1
	}
}

func (h *TagHandler) countActiveTagsByType(tx *gorm.DB, userID, tagType, excludeTagID string) (int64, error) {
	if tx == nil {
		tx = h.db
	}
	tagType = sanitizeTagType(tagType)

	var count int64
	query := tx.Model(&model.UserTag{}).
		Joins("JOIN tags ON tags.id = user_tags.tag_id").
		Where("user_tags.user_id = ? AND user_tags.deleted_at IS NULL AND user_tags.is_active = ?", userID, true).
		Where("tags.deleted_at IS NULL").
		Where("LOWER(COALESCE(NULLIF(tags.tag_type, ''), ?)) = ?", tagTypeCollective, tagType)

	if excludeTagID != "" {
		query = query.Where("user_tags.tag_id <> ?", excludeTagID)
	}

	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func validateCSSStyles(css string) error {
	// 放宽长度限制以支持复杂动画（50KB）
	if len(css) > 50000 {
		return fmt.Errorf("CSS 样式长度不能超过 50000 个字符")
	}
	lower := strings.ToLower(css)
	for _, keyword := range disallowedCSSKeywords {
		if strings.Contains(lower, keyword) {
			return fmt.Errorf("CSS 样式包含不安全的关键字: %s", keyword)
		}
	}
	// 允许 url() 但仅限于 data: 之外的相对路径或绝对路径
	// 注意：已经在黑名单中移除了 url(，如果需要完全禁止可以重新添加
	return nil
}

func validateTagTitle(title string) bool {
	trimmed := strings.TrimSpace(title)
	if trimmed == "" {
		return false
	}
	weight := 0
	for _, r := range trimmed {
		if unicode.Is(unicode.Han, r) {
			weight += 2
		} else if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			weight++
		} else {
			return false
		}
		if weight > tagTitleMaxWeight {
			return false
		}
	}
	return true
}
