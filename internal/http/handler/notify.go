package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lovewall/internal/config"
	basichttp "lovewall/internal/http"
	mw "lovewall/internal/http/middleware"
	"lovewall/internal/model"
)

type NotifyHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewNotifyHandler(db *gorm.DB, cfg *config.Config) *NotifyHandler {
	return &NotifyHandler{db: db, cfg: cfg}
}

// GET /api/notifications (auth)
func (h *NotifyHandler) List(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}
	var total int64
	var items []model.Notification
	q := h.db.Model(&model.Notification{}).Where("user_id = ?", uid)
	q.Count(&total)
	if err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": items, "page": page, "page_size": size})
}

// POST /api/notifications/:id/read (auth)
func (h *NotifyHandler) MarkRead(c *gin.Context) {
	id := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	if err := h.db.Model(&model.Notification{}).Where("id = ? AND user_id = ?", id, uid).Update("is_read", true).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	c.Status(http.StatusNoContent)
}

// GET /api/notifications/unread-count (auth)
func (h *NotifyHandler) UnreadCount(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	var count int64
	if err := h.db.Model(&model.Notification{}).
		Where("user_id = ? AND is_read = ? AND deleted_at IS NULL", uid, false).
		Count(&count).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"count": count})
}
