package handler

import (
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "gorm.io/gorm"

    "lovewall/internal/config"
    basichttp "lovewall/internal/http"
    "lovewall/internal/model"
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

type upsertBody struct {
    Title    string  `json:"title" binding:"required"`
    Content  string  `json:"content" binding:"required"`
    IsActive *bool   `json:"is_active"`
    Metadata *string `json:"metadata"`
}

func (h *AnnouncementHandler) Create(c *gin.Context) {
    var b upsertBody
    if err := c.ShouldBindJSON(&b); err != nil { basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body"); return }
    a := &model.Announcement{BaseModel: model.BaseModel{ID: uuid.NewString()}, Title: b.Title, Content: b.Content}
    if b.IsActive != nil { a.IsActive = *b.IsActive }
    a.Metadata = b.Metadata
    if err := h.db.Create(a).Error; err != nil { basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "create failed"); return }
    basichttp.JSON(c, http.StatusCreated, a)
}

func (h *AnnouncementHandler) Update(c *gin.Context) {
    id := c.Param("id")
    var b upsertBody
    if err := c.ShouldBindJSON(&b); err != nil { basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body"); return }
    updates := map[string]any{}
    if b.Title != "" { updates["title"] = b.Title }
    if b.Content != "" { updates["content"] = b.Content }
    if b.IsActive != nil { updates["is_active"] = *b.IsActive }
    if b.Metadata != nil { updates["metadata"] = *b.Metadata }
    if len(updates) == 0 { basichttp.OK(c, gin.H{"id": id}); return }
    if err := h.db.Model(&model.Announcement{}).Where("id = ? AND deleted_at IS NULL", id).Updates(updates).Error; err != nil { basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed"); return }
    var a model.Announcement
    if err := h.db.First(&a, "id = ?", id).Error; err == nil { basichttp.OK(c, a) } else { basichttp.OK(c, gin.H{"ok": true}) }
}

func (h *AnnouncementHandler) Delete(c *gin.Context) {
    id := c.Param("id")
    // Check if announcement exists
    var a model.Announcement
    if err := h.db.First(&a, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
        basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "announcement not found")
        return
    }
    // Soft delete by setting deleted_at
    now := time.Now()
    if err := h.db.Model(&model.Announcement{}).Where("id = ?", id).Update("deleted_at", now).Error; err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
        return
    }
    basichttp.OK(c, gin.H{"id": id, "deleted": true})
}

