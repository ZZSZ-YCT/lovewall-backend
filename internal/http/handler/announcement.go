package handler

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

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

var validPathPattern = regexp.MustCompile(`^/[a-zA-Z0-9/_-]*$`)

var (
	errInvalidPathChars = errors.New("path contains invalid characters")
	errPathTraversal    = errors.New("path traversal not allowed")
	errPathTooLong      = errors.New("path exceeds maximum length of 200 characters")
)

const maxPathLength = 200

// isUniqueConstraintError checks if the error is a unique constraint violation
// Works across SQLite, PostgreSQL, MySQL
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := strings.ToLower(err.Error())
	// SQLite: "UNIQUE constraint failed"
	// PostgreSQL: "duplicate key value violates unique constraint"
	// MySQL: "Duplicate entry"
	return strings.Contains(errMsg, "unique constraint") ||
		strings.Contains(errMsg, "duplicate key") ||
		strings.Contains(errMsg, "duplicate entry")
}

// normalizePath validates and normalizes announcement paths
func normalizePath(p string) (string, error) {
	// Trim whitespace
	p = strings.TrimSpace(p)

	// Check length before processing
	if len(p) > maxPathLength {
		return "", errPathTooLong
	}

	// Must start with /
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	// Clean multiple slashes
	for strings.Contains(p, "//") {
		p = strings.Replace(p, "//", "/", -1)
	}

	// Remove trailing slash AFTER cleaning multiple slashes (except for root "/")
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}

	// Check length again after normalization
	if len(p) > maxPathLength {
		return "", errPathTooLong
	}

	// Validate allowed characters (alphanumeric, /, _, -)
	if !validPathPattern.MatchString(p) {
		return "", errInvalidPathChars
	}

	// Reject path traversal attempts
	if strings.Contains(p, "..") {
		return "", errPathTraversal
	}

	return p, nil
}

func (h *AnnouncementHandler) List(c *gin.Context) {
	var items []model.Announcement
	if err := h.db.Where("deleted_at IS NULL AND is_active = ?", true).Order("created_at DESC").Find(&items).Error; err != nil {
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
	Path     string  `json:"path" binding:"required"`
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

	// Normalize and validate path
	normalizedPath, err := normalizePath(b.Path)
	if err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "INVALID_PATH", err.Error())
		return
	}

	a := &model.Announcement{Path: normalizedPath, Content: b.Content}
	if b.IsActive != nil {
		a.IsActive = *b.IsActive
	}
	a.Metadata = b.Metadata

	if err := h.db.Create(a).Error; err != nil {
		// Check for unique constraint violation (cross-database compatible)
		if isUniqueConstraintError(err) {
			basichttp.Fail(c, http.StatusConflict, "PATH_EXISTS", "announcement with this path already exists")
			return
		}
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

	if b.Path != "" {
		// Normalize and validate path
		normalizedPath, err := normalizePath(b.Path)
		if err != nil {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "INVALID_PATH", err.Error())
			return
		}
		updates["path"] = normalizedPath
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
		// Check for unique constraint violation (cross-database compatible)
		if isUniqueConstraintError(err) {
			basichttp.Fail(c, http.StatusConflict, "PATH_EXISTS", "announcement with this path already exists")
			return
		}
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

// GetByPath returns a single active announcement by path (public API)
// Path is captured with wildcard (*path) so it includes the leading slash
func (h *AnnouncementHandler) GetByPath(c *gin.Context) {
	path := c.Param("path")

	// URL decode the path (handles encoded characters like %20 for space)
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		basichttp.Fail(c, http.StatusBadRequest, "INVALID_PATH", "invalid URL encoding")
		return
	}

	// Normalize the path (same logic as Create/Update for consistency)
	normalizedPath, err := normalizePath(decodedPath)
	if err != nil {
		basichttp.Fail(c, http.StatusBadRequest, "INVALID_PATH", err.Error())
		return
	}

	var a model.Announcement
	if err := h.db.Where("path = ? AND deleted_at IS NULL AND is_active = ?", normalizedPath, true).First(&a).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "announcement not found")
		} else {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		}
		return
	}
	basichttp.OK(c, a)
}
