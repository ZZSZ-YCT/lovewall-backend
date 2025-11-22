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
)

type LogHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewLogHandler(db *gorm.DB, cfg *config.Config) *LogHandler {
	return &LogHandler{db: db, cfg: cfg}
}

// GET /api/admin/logs/submissions (super only)
func (h *LogHandler) ListSubmissionLogs(c *gin.Context) {
	if !mw.EnforceAdminMFA(c, h.db, "VIEW_LOGS") {
		return
	}
	if !mw.IsSuper(c, h.db) {
		basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return
	}
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}
	dbq := h.db.Model(&model.SubmissionLog{})
	if v := c.Query("user_id"); v != "" {
		dbq = dbq.Where("user_id = ?", v)
	}
	if v := c.Query("action"); v != "" {
		dbq = dbq.Where("action = ?", v)
	}
	if v := c.Query("object_type"); v != "" {
		dbq = dbq.Where("object_type = ?", v)
	}
	if v := c.Query("object_id"); v != "" {
		dbq = dbq.Where("object_id = ?", v)
	}
	if v := c.Query("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			dbq = dbq.Where("created_at >= ?", t)
		}
	}
	if v := c.Query("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			dbq = dbq.Where("created_at <= ?", t)
		}
	}
	var total int64
	dbq.Count(&total)
	var items []model.SubmissionLog
	if err := dbq.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": items, "page": page, "page_size": size})
}

// GET /api/admin/logs/operations (super only)
func (h *LogHandler) ListOperationLogs(c *gin.Context) {
	if !mw.EnforceAdminMFA(c, h.db, "VIEW_LOGS") {
		return
	}
	if !mw.IsSuper(c, h.db) {
		basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "superadmin required")
		return
	}
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}
	dbq := h.db.Model(&model.OperationLog{})
	if v := c.Query("admin_id"); v != "" {
		dbq = dbq.Where("admin_id = ?", v)
	}
	if v := c.Query("action"); v != "" {
		dbq = dbq.Where("action = ?", v)
	}
	if v := c.Query("object_type"); v != "" {
		dbq = dbq.Where("object_type = ?", v)
	}
	if v := c.Query("object_id"); v != "" {
		dbq = dbq.Where("object_id = ?", v)
	}
	if v := c.Query("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			dbq = dbq.Where("created_at >= ?", t)
		}
	}
	if v := c.Query("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			dbq = dbq.Where("created_at <= ?", t)
		}
	}
	var total int64
	dbq.Count(&total)
	var items []model.OperationLog
	if err := dbq.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": items, "page": page, "page_size": size})
}
