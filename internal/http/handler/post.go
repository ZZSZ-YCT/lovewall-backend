package handler

import (
    "fmt"
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "gorm.io/gorm"

    "lovewall/internal/config"
    basichttp "lovewall/internal/http"
    mw "lovewall/internal/http/middleware"
    "lovewall/internal/model"
    "lovewall/internal/storage"
)

type PostHandler struct {
    db  *gorm.DB
    cfg *config.Config
}

func NewPostHandler(db *gorm.DB, cfg *config.Config) *PostHandler {
    return &PostHandler{db: db, cfg: cfg}
}

type CreatePostForm struct {
    AuthorName string `form:"author_name" binding:"required"
json:"author_name"`
    TargetName string `form:"target_name" binding:"required"
json:"target_name"`
    Content    string `form:"content" binding:"required"
json:"content"`
}

func (h *PostHandler) CreatePost(c *gin.Context) {
    var form CreatePostForm
    if err := c.ShouldBind(&form); err != nil {
        basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid form")
        return
    }
    uid, _ := c.Get(mw.CtxUserID)
    var imagePath *string

    file, header, err := c.Request.FormFile("image")
    if err == nil && header != nil {
        defer file.Close()
        // Validate MIME & size
        if header.Size > h.cfg.MaxUploadMB*1024*1024 {
            basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "file too large")
            return
        }
        buf := make([]byte, 512)
        n, _ := file.Read(buf)
        mime := http.DetectContentType(buf[:n])
        if ext := storage.ExtFromMIME(mime); ext == "" {
            basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "unsupported mime")
            return
        } else {
            // rewind
            if seeker, ok := file.(interface{ Seek(int64, int) (int64, error) }); ok {
                _, _ = seeker.Seek(0, 0)
            }
            lp := &storage.LocalProvider{BaseDir: h.cfg.UploadDir}
            savedName := uuid.NewString() + ext
            if _, err := lp.Save(c, file, savedName); err != nil {
                basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "save file failed")
                return
            }
            url := storage.JoinURL(h.cfg.UploadBaseURL, savedName)
            imagePath = &url
        }
    }

    p := &model.Post{
        BaseModel:  model.BaseModel{ID: uuid.NewString()},
        AuthorID:   uid.(string),
        AuthorName: form.AuthorName,
        TargetName: form.TargetName,
        Content:    form.Content,
        ImagePath:  imagePath,
        Status:     0,
        IsPinned:   false,
        IsFeatured: false,
    }
    if err := h.db.Create(p).Error; err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "create post failed")
        return
    }
    basichttp.JSON(c, http.StatusCreated, p)
}

func (h *PostHandler) ListPosts(c *gin.Context) {
    page := queryInt(c, "page", 1)
    size := queryInt(c, "page_size", 20)
    if size > 100 {
        size = 100
    }
    var items []model.Post
    var total int64
    q := h.db.Model(&model.Post{}).Where("status = 0 AND deleted_at IS NULL")

    if v := c.Query("featured"); v == "true" {
        q = q.Where("is_featured = 1")
    }
    if v := c.Query("pinned"); v == "true" {
        q = q.Where("is_pinned = 1")
    }
    q.Count(&total)
    q = q.Order("created_at DESC").Offset((page - 1) * size).Limit(size)
    if err := q.Find(&items).Error; err != nil {
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

func (h *PostHandler) GetPost(c *gin.Context) {
    id := c.Param("id")
    var p model.Post
    if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
        basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
        return
    }
    if p.Status != 0 {
        // Only admins can view hidden/deleted (not wired here); return 404
        basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
        return
    }
    basichttp.OK(c, p)
}

func queryInt(c *gin.Context, key string, def int) int {
    if v := c.Query(key); v != "" {
        var x int
        if _, err := fmt.Sscanf(v, "%d", &x); err == nil {
            return x
        }
    }
    return def
}

func since(t time.Time) string { return time.Since(t).String() }

// ----- Management endpoints -----

type toggleBody struct{ Value bool `json:"pin"` }

func (h *PostHandler) Pin(c *gin.Context) {
    var body struct{ Pin bool `json:"pin"` }
    if err := c.ShouldBindJSON(&body); err != nil { basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body"); return }
    id := c.Param("id")
    if err := h.db.Model(&model.Post{}).Where("id = ? AND deleted_at IS NULL", id).Update("is_pinned", body.Pin).Error; err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed"); return
    }
    basichttp.OK(c, gin.H{"id": id, "is_pinned": body.Pin})
}

func (h *PostHandler) Feature(c *gin.Context) {
    var body struct{ Feature bool `json:"feature"` }
    if err := c.ShouldBindJSON(&body); err != nil { basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body"); return }
    id := c.Param("id")
    if err := h.db.Model(&model.Post{}).Where("id = ? AND deleted_at IS NULL", id).Update("is_featured", body.Feature).Error; err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed"); return
    }
    basichttp.OK(c, gin.H{"id": id, "is_featured": body.Feature})
}

func (h *PostHandler) Hide(c *gin.Context) {
    var body struct{ Hide bool `json:"hide"` }
    if err := c.ShouldBindJSON(&body); err != nil { basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body"); return }
    id := c.Param("id")
    newStatus := 0
    if body.Hide { newStatus = 1 }
    if err := h.db.Model(&model.Post{}).Where("id = ? AND deleted_at IS NULL", id).Update("status", newStatus).Error; err != nil {
        basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed"); return
    }
    basichttp.OK(c, gin.H{"id": id, "status": newStatus})
}

type updatePostBody struct {
    AuthorName *string `json:"author_name"`
    TargetName *string `json:"target_name"`
    Content    *string `json:"content"`
}

// Edit: author within 15m, else requires EDIT_POST
func (h *PostHandler) Update(c *gin.Context) {
    id := c.Param("id")
    var p model.Post
    if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil { basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found"); return }
    uid, _ := c.Get(mw.CtxUserID)
    canEdit := uid == p.AuthorID
    if !canEdit {
        // require perm EDIT_POST or superadmin
        if !mw.IsSuper(c) {
            var cnt int64
            h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id=? AND permission=?", uid, "EDIT_POST").Scan(&cnt)
            if cnt == 0 { basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission"); return }
        }
        canEdit = true
    } else {
        // author limited time window
        if time.Since(p.CreatedAt) > 15*time.Minute {
            // need EDIT_POST if beyond window
            if !mw.IsSuper(c) {
                var cnt int64
                h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id=? AND permission=?", uid, "EDIT_POST").Scan(&cnt)
                if cnt == 0 { basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "edit window closed"); return }
            }
        }
    }
    var body updatePostBody
    if err := c.ShouldBindJSON(&body); err != nil { basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body"); return }
    updates := map[string]any{}
    if body.AuthorName != nil { updates["author_name"] = *body.AuthorName }
    if body.TargetName != nil { updates["target_name"] = *body.TargetName }
    if body.Content != nil { updates["content"] = *body.Content }
    if len(updates) == 0 { basichttp.OK(c, p); return }
    if err := h.db.Model(&model.Post{}).Where("id = ?", id).Updates(updates).Error; err != nil { basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed"); return }
    if err := h.db.First(&p, "id = ?", id).Error; err == nil { basichttp.OK(c, p) } else { basichttp.OK(c, gin.H{"ok": true}) }
}

// Delete (soft): author or DELETE_POST
func (h *PostHandler) Delete(c *gin.Context) {
    id := c.Param("id")
    var p model.Post
    if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil { basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found"); return }
    uid, _ := c.Get(mw.CtxUserID)
    if uid != p.AuthorID {
        if !mw.IsSuper(c) {
            var cnt int64
            h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id=? AND permission=?", uid, "DELETE_POST").Scan(&cnt)
            if cnt == 0 { basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission"); return }
        }
    }
    if err := h.db.Model(&model.Post{}).Where("id = ?", id).Update("status", 2).Error; err != nil { basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed"); return }
    basichttp.OK(c, gin.H{"id": id, "status": 2})
}
