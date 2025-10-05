package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lovewall/internal/config"
	basichttp "lovewall/internal/http"
	mw "lovewall/internal/http/middleware"
	"lovewall/internal/model"
	"lovewall/internal/service"
)

type AnnouncementHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewAnnouncementHandler(db *gorm.DB, cfg *config.Config) *AnnouncementHandler {
	return &AnnouncementHandler{db: db, cfg: cfg}
}

func (h *AnnouncementHandler) List(c *gin.Context) {
	var items []model.Announcement
	if err := h.db.Where("deleted_at IS NULL AND is_active = 1").Order("created_at DESC").Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, items)
}

// AdminList returns all announcements (including stopped ones) for admin use
func (h *AnnouncementHandler) AdminList(c *gin.Context) {
	var items []model.Announcement
	if err := h.db.Where("deleted_at IS NULL").Order("created_at DESC").Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, items)
}

type upsertBody struct {
	Title    string  `json:"title" binding:"required"`
	Content  string  `json:"content" binding:"required"`
	IsActive *bool   `json:"is_active"`
	Metadata *string `json:"metadata"`
}

func (h *AnnouncementHandler) Create(c *gin.Context) {
	var b upsertBody
	if err := c.ShouldBindJSON(&b); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	a := &model.Announcement{Title: b.Title, Content: b.Content}
	if b.IsActive != nil {
		a.IsActive = *b.IsActive
	}
	a.Metadata = b.Metadata
	if err := h.db.Create(a).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "create failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "create_announcement", "announcement", a.ID, nil)
		}
	}
	basichttp.JSON(c, http.StatusCreated, a)
}

func (h *AnnouncementHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var b upsertBody
	if err := c.ShouldBindJSON(&b); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	updates := map[string]any{}
	if b.Title != "" {
		updates["title"] = b.Title
	}
	if b.Content != "" {
		updates["content"] = b.Content
	}
	if b.IsActive != nil {
		updates["is_active"] = *b.IsActive
	}
	if b.Metadata != nil {
		updates["metadata"] = *b.Metadata
	}
	if len(updates) == 0 {
		basichttp.OK(c, gin.H{"id": id})
		return
	}
	if err := h.db.Model(&model.Announcement{}).Where("id = ? AND deleted_at IS NULL", id).Updates(updates).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	var a model.Announcement
	if err := h.db.First(&a, "id = ?", id).Error; err == nil {
		if uid, ok := c.Get(mw.CtxUserID); ok {
			if uidStr, ok2 := uid.(string); ok2 {
				service.LogOperation(h.db, uidStr, "update_announcement", "announcement", id, nil)
			}
		}
		basichttp.OK(c, a)
	} else {
		basichttp.OK(c, gin.H{"ok": true})
	}
}

func (h *AnnouncementHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	// Check if announcement exists
	var a model.Announcement
	if err := h.db.First(&a, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "announcement not found")
		return
	}
	// Hard delete
	if err := h.db.Unscoped().Delete(&a).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "delete_announcement", "announcement", id, nil)
		}
	}
	basichttp.OK(c, gin.H{"id": id, "deleted": true})
}
