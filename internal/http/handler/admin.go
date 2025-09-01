package handler

import (
    "fmt"
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "gorm.io/gorm"

    "lovewall/internal/config"
    basichttp "lovewall/internal/http"
    mw "lovewall/internal/http/middleware"
    "lovewall/internal/model"
)

type AdminHandler struct {
    db  *gorm.DB
    cfg *config.Config
}

func NewAdminHandler(db *gorm.DB, cfg *config.Config) *AdminHandler {
    return &AdminHandler{db: db, cfg: cfg}
}

// Only superadmin can overwrite permissions
type permBody struct {
    Permissions []string `json:"permissions" binding:"required"`
}

func (h *AdminHandler) SetUserPermissions(c *gin.Context) {
    if !mw.IsSuper(c) {
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
    var body permBody
    if err := c.ShouldBindJSON(&body); err != nil { basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body"); return }
    // sanitize
    uniq := map[string]struct{}{}
    perms := make([]string, 0, len(body.Permissions))
    for _, p := range body.Permissions {
        p = strings.TrimSpace(p)
        if p == "" { continue }
        if _, ok := uniq[p]; ok { continue }
        uniq[p] = struct{}{}
        perms = append(perms, p)
    }
    tx := h.db.Begin()
    // Use Unscoped to permanently delete old permissions for this operation
    if err := tx.Unscoped().Where("user_id = ?", id).Delete(&model.UserPermission{}).Error; err != nil { tx.Rollback(); basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed"); return }
    for _, p := range perms {
        up := model.UserPermission{BaseModel: model.BaseModel{ID: uuid.NewString()}, UserID: id, Permission: p}
        if err := tx.Create(&up).Error; err != nil { tx.Rollback(); basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed"); return }
    }
    if err := tx.Commit().Error; err != nil { basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed"); return }
    basichttp.OK(c, gin.H{"user_id": id, "permissions": perms})
}

// List users (MANAGE_USERS)
func (h *AdminHandler) ListUsers(c *gin.Context) {
    q := strings.TrimSpace(c.Query("q"))
    status := strings.TrimSpace(c.Query("status"))
    page := 1; size := 20
    if v := c.Query("page"); v != "" { _, _ = fmt.Sscanf(v, "%d", &page) }
    if v := c.Query("page_size"); v != "" { _, _ = fmt.Sscanf(v, "%d", &size); if size > 100 { size = 100 } }
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
    if err := dbq.Order("created_at DESC").Offset((page-1)*size).Limit(size).Find(&users).Error; err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
        return
    }
    items := make([]gin.H, 0, len(users))
    for i := range users { items = append(items, sanitizeUser(&users[i])) }
    basichttp.OK(c, gin.H{"total": total, "items": items, "page": page, "page_size": size})
}

