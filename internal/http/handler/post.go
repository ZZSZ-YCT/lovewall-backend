package handler

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"lovewall/internal/config"
	basichttp "lovewall/internal/http"
	mw "lovewall/internal/http/middleware"
	"lovewall/internal/model"
	"lovewall/internal/service"
	"lovewall/internal/storage"
)

type PostHandler struct {
	db         *gorm.DB
	cfg        *config.Config
	tagService *service.UserTagService
}

func NewPostHandler(db *gorm.DB, cfg *config.Config) *PostHandler {
	return &PostHandler{
		db:         db,
		cfg:        cfg,
		tagService: service.NewUserTagService(db),
	}
}

type CreatePostForm struct {
	AuthorName    string `form:"author_name" json:"author_name"`
	TargetName    string `form:"target_name" json:"target_name"`
	Content       string `form:"content" binding:"required" json:"content"`
	ConfessorMode string `form:"confessor_mode" json:"confessor_mode"` // optional: "self" or "custom"
	CardType      string `form:"card_type" json:"card_type"`
}

func (h *PostHandler) CreatePost(c *gin.Context) {
	var form CreatePostForm
	if err := c.ShouldBind(&form); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid form")
		return
	}
	cardType := strings.ToLower(strings.TrimSpace(form.CardType))
	if cardType == "" {
		cardType = "confession"
	}
	if cardType != "confession" && cardType != "social" {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid card_type")
		return
	}
	targetName := strings.TrimSpace(form.TargetName)
	if cardType == "confession" && targetName == "" {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "target_name is required for confession cards")
		return
	}
	uid, _ := c.Get(mw.CtxUserID)
	// Handle multiple images: up to 9 images, each <= 5MB
	const maxImages = 9
	const perFileLimitBytes int64 = 5 * 1024 * 1024
	imageURLs := make([]string, 0)
	if formdata, err := c.MultipartForm(); err == nil && formdata != nil {
		files := formdata.File["images"]
		if len(files) == 0 {
			// Fallback to single key "image"
			if single := formdata.File["image"]; len(single) > 0 {
				files = single
			}
		}
		if len(files) > 0 {
			if len(files) > maxImages {
				basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", fmt.Sprintf("too many images (max %d)", maxImages))
				return
			}
			lp := &storage.LocalProvider{BaseDir: h.cfg.UploadDir}
			for _, fh := range files {
				if fh.Size > perFileLimitBytes {
					basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "file too large (limit 5MB per image)")
					return
				}
				f, err := fh.Open()
				if err != nil {
					basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "open file failed")
					return
				}
				// Read header for MIME detection
				buf := make([]byte, 512)
				n, err := f.Read(buf)
				if err != nil && err != io.EOF {
					f.Close()
					basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "read file failed")
					return
				}
				mime := http.DetectContentType(buf[:n])
				ext := storage.ExtFromMIME(mime)
				if ext == "" {
					f.Close()
					basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "unsupported mime")
					return
				}
				// rewind if possible
				if seeker, ok := f.(interface {
					Seek(int64, int) (int64, error)
				}); ok {
					if _, err := seeker.Seek(0, 0); err != nil {
						f.Close()
						basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "file seek failed")
						return
					}
				}
				savedName := uuid.NewString() + ext
				if _, err := lp.Save(c, f, savedName); err != nil {
					f.Close()
					basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "save file failed")
					return
				}
				f.Close()
				url := storage.JoinURL(h.cfg.UploadBaseURL, savedName)
				imageURLs = append(imageURLs, url)
			}
		}
	}

	// Determine confessor mode and author name to store
	mode := strings.ToLower(strings.TrimSpace(form.ConfessorMode))
	if mode == "" {
		mode = "custom"
	}
	var authorName string
	if mode == "self" {
		authorName = h.getUserDisplayName(uid.(string))
		if strings.TrimSpace(authorName) == "" {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "could not resolve author name for self mode")
			return
		}
	} else {
		authorName = strings.TrimSpace(form.AuthorName)
		if authorName == "" {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "author_name is required when confessor_mode is custom")
			return
		}
		mode = "custom"
	}

	// Length validation
	if len([]rune(form.Content)) > 1000 {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "内容长度超过1000字")
		return
	}
	if len([]rune(form.Content)) > h.cfg.MaxPostChars {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", fmt.Sprintf("内容长度超过限制(%d)", h.cfg.MaxPostChars))
		return
	}
	if len([]rune(authorName)) > 200 {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "author_name过长")
		return
	}
	if len([]rune(targetName)) > 200 {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "target_name过长")
		return
	}

	p := &model.Post{
		AuthorID:      uid.(string),
		AuthorName:    authorName,
		TargetName:    targetName,
		Content:       form.Content,
		Status:        1, // hidden while awaiting AI moderation
		IsPinned:      false,
		IsFeatured:    false,
		ConfessorMode: &mode,
		CardType:      &cardType,
		AuditStatus:   1, // pending
		AuditMsg:      nil,
	}
	if err := h.db.Create(p).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "create post failed")
		return
	}
	// Save PostImage rows if any
	if len(imageURLs) > 0 {
		imgs := make([]model.PostImage, 0, len(imageURLs))
		for idx, url := range imageURLs {
			imgs = append(imgs, model.PostImage{PostID: p.ID, URL: url, SortOrder: idx})
		}
		if err := h.db.Create(&imgs).Error; err != nil {
			// Non-fatal to post creation; log and continue
		}
	}
	// Log submission
	if uidStr, ok := uid.(string); ok {
		service.LogSubmission(h.db, uidStr, "post_create", "post", p.ID, map[string]any{"target_name": p.TargetName, "ip": c.ClientIP()})
	}
	// Enqueue async moderation
	service.EnqueuePostModeration(p.ID)
	basichttp.JSON(c, http.StatusCreated, h.enrichPostWithUserTag(p))
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
		"items":     h.enrichPostsWithUserTags(items),
		"page":      page,
		"page_size": size,
	})
}

// GET /api/users/:id/posts (public)
// Lists visible posts authored by the specified user.
func (h *PostHandler) ListByUser(c *gin.Context) {
	userID := c.Param("id")
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	var items []model.Post
	q := h.db.Model(&model.Post{}).
		Where("author_id = ? AND status = 0 AND deleted_at IS NULL", userID)
	q.Count(&total)
	if err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": h.enrichPostsWithUserTags(items), "page": page, "page_size": size})
}

func (h *PostHandler) GetPost(c *gin.Context) {
	id := c.Param("id")
	var p model.Post
	if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	// Check visibility: status=0 is public, others need admin permission
	if p.Status != 0 {
		uid, hasAuth := c.Get(mw.CtxUserID)
		if !hasAuth {
			basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
			return
		}
		// Allow if superadmin or has any post moderation permission
		if !mw.IsSuper(c, h.db) {
			var cnt int64
			h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL",
				uid, "MANAGE_POSTS").Scan(&cnt)
			if cnt == 0 {
				basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
				return
			}
		}
	}
	// Count this request as a view (all requests, logged-in or not)
	_ = h.db.Model(&model.Post{}).Where("id = ?", id).Update("view_count", gorm.Expr("view_count + 1")).Error
	basichttp.OK(c, h.enrichPostWithUserTag(&p))
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

// enrichPostWithUserTag adds user tag information to post response
func (h *PostHandler) enrichPostWithUserTag(post *model.Post) gin.H {
	if post == nil {
		return gin.H{}
	}

	items := h.enrichPostsWithUserTags([]model.Post{*post})
	if len(items) > 0 {
		return items[0]
	}
	return gin.H{}
}

// getPostImages returns image URLs for a post in order
func (h *PostHandler) getPostImages(postID string) []string {
	var imgs []model.PostImage
	urls := []string{}
	if err := h.db.Where("post_id = ?", postID).Order("sort_order ASC, created_at ASC").Find(&imgs).Error; err == nil {
		urls = make([]string, 0, len(imgs))
		for _, im := range imgs {
			urls = append(urls, im.URL)
		}
	}
	return urls
}

// computeAuthorDisplayName applies confessor mode to derive visible author name
func (h *PostHandler) computeAuthorDisplayName(post *model.Post) string {
	if post.ConfessorMode != nil && *post.ConfessorMode == "self" {
		return h.getUserDisplayName(post.AuthorID)
	}
	return post.AuthorName
}

func (h *PostHandler) getUserDisplayName(userID string) string {
	var u model.User
	if err := h.db.Unscoped().Select("username, display_name").First(&u, "id = ?", userID).Error; err == nil {
		if u.DisplayName != nil && *u.DisplayName != "" {
			return *u.DisplayName
		}
		return u.Username
	}
	return ""
}

// batchGetUserDisplayNames resolves display names for a set of user IDs in one query.
func (h *PostHandler) batchGetUserDisplayNames(userIDs []string) map[string]string {
	result := make(map[string]string)
	if len(userIDs) == 0 {
		return result
	}

	unique := make([]string, 0, len(userIDs))
	seen := make(map[string]struct{}, len(userIDs))
	for _, id := range userIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return result
	}

	var users []model.User
	if err := h.db.Unscoped().Select("id, username, display_name").
		Where("id IN ?", unique).
		Find(&users).Error; err != nil {
		return result
	}
	for i := range users {
		name := users[i].Username
		if users[i].DisplayName != nil && *users[i].DisplayName != "" {
			name = *users[i].DisplayName
		}
		result[users[i].ID] = name
	}
	return result
}

// getUserDisplayNameCached gets a display name from a precomputed map.
func getUserDisplayNameCached(userID string, nameMap map[string]string) string {
	if nameMap == nil {
		return ""
	}
	if name, ok := nameMap[userID]; ok {
		return name
	}
	return ""
}

// enrichPostsWithUserTags adds user tag information to multiple posts (optimized batch query)
func (h *PostHandler) enrichPostsWithUserTags(posts []model.Post) []gin.H {
	if len(posts) == 0 {
		return []gin.H{}
	}

	authorIDs := make([]string, 0, len(posts))
	authorIDSet := make(map[string]bool)
	for i := range posts {
		if !authorIDSet[posts[i].AuthorID] {
			authorIDs = append(authorIDs, posts[i].AuthorID)
			authorIDSet[posts[i].AuthorID] = true
		}
	}

	userTags, err := h.tagService.GetActiveUserTagsBatch(authorIDs)
	if err != nil {
		userTags = make(map[string]*model.Tag)
	}

	var users []model.User
	userMap := make(map[string]*model.User)
	if err := h.db.Select("id, username, display_name, is_superadmin, avatar_url, is_online, last_heartbeat").
		Where("id IN ? AND deleted_at IS NULL", authorIDs).
		Find(&users).Error; err == nil {
		for i := range users {
			userMap[users[i].ID] = &users[i]
		}
	}

	type PermCount struct {
		UserID string
		Count  int64
	}
	var permCounts []PermCount
	permMap := make(map[string]bool)
	if err := h.db.Model(&model.UserPermission{}).
		Select("user_id, COUNT(*) as count").
		Where("user_id IN ? AND deleted_at IS NULL", authorIDs).
		Group("user_id").
		Scan(&permCounts).Error; err == nil {
		for _, pc := range permCounts {
			permMap[pc.UserID] = pc.Count > 0
		}
	}

	postIDs := make([]string, len(posts))
	for i := range posts {
		postIDs[i] = posts[i].ID
	}
	var allImages []model.PostImage
	imageMap := make(map[string][]string)
	if err := h.db.Where("post_id IN ?", postIDs).
		Order("post_id, sort_order ASC, created_at ASC").
		Find(&allImages).Error; err == nil {
		for _, img := range allImages {
			imageMap[img.PostID] = append(imageMap[img.PostID], img.URL)
		}
	}

	confessorUserIDs := make([]string, 0, len(posts))
	confessorSet := make(map[string]struct{}, len(posts))
	for i := range posts {
		if posts[i].ConfessorMode != nil && *posts[i].ConfessorMode == "self" {
			if _, ok := confessorSet[posts[i].AuthorID]; !ok {
				confessorSet[posts[i].AuthorID] = struct{}{}
				confessorUserIDs = append(confessorUserIDs, posts[i].AuthorID)
			}
		}
	}
	displayNameMap := h.batchGetUserDisplayNames(confessorUserIDs)

	result := make([]gin.H, 0, len(posts))
	for i := range posts {
		post := &posts[i]

		cardType := "confession"
		if post.CardType != nil {
			trimmed := strings.TrimSpace(*post.CardType)
			if trimmed != "" {
				cardType = trimmed
			}
		}

		authorName := post.AuthorName
		if post.ConfessorMode != nil && *post.ConfessorMode == "self" {
			if name := getUserDisplayNameCached(post.AuthorID, displayNameMap); name != "" {
				authorName = name
			}
		}

		item := gin.H{
			"id":                      post.ID,
			"author_id":               post.AuthorID,
			"author_name":             authorName,
			"author_display_name":     nil,
			"author_avatar_url":       nil,
			"author_is_online":        false,
			"author_last_heartbeat":   nil,
			"target_name":             post.TargetName,
			"content":                 post.Content,
			"images":                  imageMap[post.ID],
			"status":                  post.Status,
			"is_pinned":               post.IsPinned,
			"is_featured":             post.IsFeatured,
			"is_locked":               post.IsLocked,
			"confessor_mode":          post.ConfessorMode,
			"card_type":               cardType,
			"metadata":                post.Metadata,
			"created_at":              post.CreatedAt,
			"updated_at":              post.UpdatedAt,
			"author_tag":              nil,
			"is_author_admin":         false,
			"view_count":              post.ViewCount,
			"comment_count":           post.CommentCount,
			"audit_status":            post.AuditStatus,
			"audit_msg":               post.AuditMsg,
			"manual_review_requested": post.ManualReviewRequested,
			"is_pending_review":       post.AuditStatus == 1,
		}

		if tag, ok := userTags[post.AuthorID]; ok && tag != nil {
			item["author_tag"] = gin.H{
				"name":             tag.Name,
				"title":            tag.Title,
				"background_color": tag.BackgroundColor,
				"text_color":       tag.TextColor,
				"tag_type":         tag.TagType,
				"css_styles":       tag.CssStyles,
			}
		}

		if user, ok := userMap[post.AuthorID]; ok {
			if user.IsSuperadmin {
				item["is_author_admin"] = true
			} else if permMap[post.AuthorID] {
				item["is_author_admin"] = true
			}
			// Add complete author information
			if user.DisplayName != nil && *user.DisplayName != "" {
				item["author_display_name"] = *user.DisplayName
			} else {
				item["author_display_name"] = user.Username
			}
			item["author_avatar_url"] = user.AvatarURL
			item["author_is_online"] = user.IsOnline
			item["author_last_heartbeat"] = user.LastHeartbeat
		}

		result = append(result, item)
	}

	return result
}

// ----- Management endpoints -----

// POST /api/posts/:id/request-review (auth; owner only)
func (h *PostHandler) RequestManualReview(c *gin.Context) {
	id := c.Param("id")
	var p model.Post
	if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	uid, _ := c.Get(mw.CtxUserID)
	uidStr, _ := uid.(string)
	if p.AuthorID != uidStr {
		basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "not owner")
		return
	}
	if p.AuditStatus != 2 { // only when rejected
		basichttp.OK(c, gin.H{"post_id": p.ID, "manual_review_requested": p.ManualReviewRequested})
		return
	}
	if err := h.db.Model(&model.Post{}).Where("id = ?", id).Update("manual_review_requested", true).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	// Notify all reviewers (superadmins or users with any post perms)
	// Fetch reviewer user IDs
	reviewerIDs := map[string]struct{}{}
	var adminIDs []string
	h.db.Model(&model.User{}).Where("is_superadmin = 1 AND deleted_at IS NULL").Pluck("id", &adminIDs)
	for _, id := range adminIDs {
		reviewerIDs[id] = struct{}{}
	}
	perms := []string{"MANAGE_POSTS"}
	var upIDs []string
	h.db.Model(&model.UserPermission{}).Where("permission IN ? AND deleted_at IS NULL", perms).Pluck("user_id", &upIDs)
	for _, id2 := range upIDs {
		reviewerIDs[id2] = struct{}{}
	}
	// Build notification content with placeholders
	aiMsg := ""
	if p.AuditMsg != nil {
		aiMsg = *p.AuditMsg
	}
	requester := h.getUserDisplayName(uidStr)
	if strings.TrimSpace(requester) == "" {
		requester = "用户"
	}
	content := h.buildManualReviewNotificationContent(&p, requester, aiMsg)
	for rid := range reviewerIDs {
		if rid == p.AuthorID {
			continue
		}
		service.Notify(h.db, rid, "人工复核申请", content, map[string]any{"post_id": p.ID})
	}
	basichttp.OK(c, gin.H{"post_id": p.ID, "manual_review_requested": true})
}

// POST /api/posts/:id/view (auth)
// Count a unique view by the current user. Each user counted only once.
func (h *PostHandler) View(c *gin.Context) {
	id := c.Param("id")
	// Ensure post exists and is not soft-deleted
	var p model.Post
	if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	uidVal, _ := c.Get(mw.CtxUserID)
	uid := uidVal.(string)
	tx := h.db.Begin()
	pv := &model.PostView{UserID: uid, PostID: id}
	if err := tx.Create(pv).Error; err != nil {
		// Likely already exists due to unique index; ignore and commit no-op
		tx.Rollback()
		basichttp.OK(c, gin.H{"counted": false})
		return
	}
	// Increment view count atomically
	if err := tx.Model(&model.Post{}).Where("id = ?", id).Update("view_count", gorm.Expr("view_count + 1")).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "increment failed")
		return
	}
	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}
	basichttp.OK(c, gin.H{"counted": true})
}

// GET /api/posts/:id/stats (public)
func (h *PostHandler) Stats(c *gin.Context) {
	id := c.Param("id")
	var p model.Post
	if err := h.db.Select("id, view_count, comment_count").First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	basichttp.OK(c, gin.H{"id": p.ID, "view_count": p.ViewCount, "comment_count": p.CommentCount})
}

func (h *PostHandler) Pin(c *gin.Context) {
	var body struct {
		Pin    bool    `json:"pin"`
		Reason *string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	id := c.Param("id")
	if err := h.db.Model(&model.Post{}).Where("id = ? AND deleted_at IS NULL", id).Update("is_pinned", body.Pin).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	var p model.Post
	if err := h.db.First(&p, "id = ?", id).Error; err == nil {
		operator := h.resolveOperatorName(c)
		reason := strings.TrimSpace(h.pickReason(body.Reason))
		title := "帖子取消置顶"
		if body.Pin {
			title = "帖子被置顶"
			if reason == "" {
				reason = "管理员将帖子置顶以获得更多曝光。"
			}
		} else {
			if reason == "" {
				reason = "管理员取消了置顶，帖子已恢复普通排序。"
			}
		}
		content := h.buildPostNotificationContent(title, &p, operator, reason)
		service.Notify(h.db, p.AuthorID, title, content, map[string]any{"post_id": p.ID})
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			action := "pin_post"
			if !body.Pin {
				action = "unpin_post"
			}
			service.LogOperation(h.db, uidStr, action, "post", id, nil)
		}
	}
	basichttp.OK(c, gin.H{"id": id, "is_pinned": body.Pin})
}

func (h *PostHandler) Feature(c *gin.Context) {
	var body struct {
		Feature bool    `json:"feature"`
		Reason  *string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	id := c.Param("id")
	if err := h.db.Model(&model.Post{}).Where("id = ? AND deleted_at IS NULL", id).Update("is_featured", body.Feature).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	var p model.Post
	if err := h.db.First(&p, "id = ?", id).Error; err == nil {
		operator := h.resolveOperatorName(c)
		reason := strings.TrimSpace(h.pickReason(body.Reason))
		title := "帖子取消加精"
		if body.Feature {
			title = "帖子被加精"
			if reason == "" {
				reason = "管理员将帖子加精以推荐给更多用户。"
			}
		} else {
			if reason == "" {
				reason = "管理员取消了加精，帖子显示恢复为普通状态。"
			}
		}
		content := h.buildPostNotificationContent(title, &p, operator, reason)
		service.Notify(h.db, p.AuthorID, title, content, map[string]any{"post_id": p.ID})
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			action := "feature_post"
			if !body.Feature {
				action = "unfeature_post"
			}
			service.LogOperation(h.db, uidStr, action, "post", id, nil)
		}
	}
	basichttp.OK(c, gin.H{"id": id, "is_featured": body.Feature})
}

func (h *PostHandler) LockPost(c *gin.Context) {
	id := c.Param("id")
	if err := h.db.Model(&model.Post{}).Where("id = ? AND deleted_at IS NULL", id).Update("is_locked", true).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "lock_post", "post", id, nil)
		}
	}
	basichttp.OK(c, gin.H{"id": id, "is_locked": true})
}

func (h *PostHandler) UnlockPost(c *gin.Context) {
	id := c.Param("id")
	if err := h.db.Model(&model.Post{}).Where("id = ? AND deleted_at IS NULL", id).Update("is_locked", false).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "unlock_post", "post", id, nil)
		}
	}
	basichttp.OK(c, gin.H{"id": id, "is_locked": false})
}

func (h *PostHandler) Hide(c *gin.Context) {
	var body struct {
		Hide   bool    `json:"hide"`
		Reason *string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	id := c.Param("id")

	// 检查帖子是否存在及审核状态
	var p model.Post
	if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}

	// 禁止取消隐藏待审核帖子
	if !body.Hide && p.AuditStatus == 1 {
		basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "cannot unhide pending review post, use approve instead")
		return
	}

	newStatus := 0
	if body.Hide {
		newStatus = 1
	}
	if err := h.db.Model(&model.Post{}).Where("id = ?", id).Update("status", newStatus).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}

	operator := h.resolveOperatorName(c)
	title := "帖子取消隐藏"
	reason := strings.TrimSpace(h.pickReason(body.Reason))
	if body.Hide {
		title = "帖子被隐藏"
		if reason == "" {
			if p.AuditMsg != nil && strings.TrimSpace(*p.AuditMsg) != "" {
				reason = *p.AuditMsg
			} else {
				reason = "管理员暂时隐藏了该帖子，等待内容调整或人工复核。"
			}
		}
	} else if reason == "" {
		reason = "管理员重新开放了该帖子，现已对所有用户可见。"
	}
	content := h.buildPostNotificationContent(title, &p, operator, reason)
	service.Notify(h.db, p.AuthorID, title, content, map[string]any{"post_id": p.ID})

	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			action := "unhide_post"
			if body.Hide {
				action = "hide_post"
			}
			service.LogOperation(h.db, uidStr, action, "post", id, nil)
		}
	}
	basichttp.OK(c, gin.H{"id": id, "status": newStatus})
}

type updatePostBody struct {
	AuthorName *string `json:"author_name"`
	TargetName *string `json:"target_name"`
	Content    *string `json:"content"`
}

// Edit: author within 15m, else requires MANAGE_POSTS
func (h *PostHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var p model.Post
	if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	uid, _ := c.Get(mw.CtxUserID)
	// Only allow admins to edit posts, authors cannot edit
	if !mw.IsSuper(c, h.db) {
		var cnt int64
		h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id=? AND permission=? AND deleted_at IS NULL", uid, "MANAGE_POSTS").Scan(&cnt)
		if cnt == 0 {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "only admin can edit posts")
			return
		}
	}
	var body updatePostBody
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}
	updates := map[string]any{}
	if body.AuthorName != nil {
		updates["author_name"] = *body.AuthorName
	}
	if body.TargetName != nil {
		updates["target_name"] = *body.TargetName
	}
	if body.Content != nil {
		if len([]rune(*body.Content)) > 1000 {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "内容长度超过1000字")
			return
		}
		if len([]rune(*body.Content)) > h.cfg.MaxPostChars {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", fmt.Sprintf("内容长度超过限制(%d)", h.cfg.MaxPostChars))
			return
		}
		updates["content"] = *body.Content
	}
	if len(updates) == 0 {
		basichttp.OK(c, p)
		return
	}
	// Apply updates and set pending moderation again
	updates["status"] = 1
	updates["audit_status"] = 1
	updates["audit_msg"] = nil
	updates["manual_review_requested"] = false
	if err := h.db.Model(&model.Post{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}
	// enqueue moderation
	service.EnqueuePostModeration(id)
	if err := h.db.First(&p, "id = ?", id).Error; err == nil {
		basichttp.OK(c, p)
	} else {
		basichttp.OK(c, gin.H{"ok": true})
	}
}

// GetPostLockStatus returns lock status of a post
// GET /api/posts/:id/lock-status (public)
func (h *PostHandler) GetPostLockStatus(c *gin.Context) {
	id := c.Param("id")
	var post model.Post
	if err := h.db.Select("id, is_locked").First(&post, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	basichttp.OK(c, gin.H{"id": id, "is_locked": post.IsLocked})
}

// Delete (soft): author or MANAGE_POSTS
func (h *PostHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	var p model.Post
	if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	uid, _ := c.Get(mw.CtxUserID)
	operator := h.resolveOperatorName(c)
	if uid != p.AuthorID {
		if !mw.IsSuper(c, h.db) {
			var cnt int64
			h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id=? AND permission=? AND deleted_at IS NULL", uid, "MANAGE_POSTS").Scan(&cnt)
			if cnt == 0 {
				basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
				return
			}
		}
	}
	// Hard delete: remove post and its comments and images in a transaction
	tx := h.db.Begin()
	if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.Comment{}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.PostImage{}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	if err := tx.Unscoped().Delete(&p).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	// Log delete (author or admin)
	if uidStr, ok := (func() (string, bool) {
		v, ok := c.Get(mw.CtxUserID)
		if !ok {
			return "", false
		}
		s, ok2 := v.(string)
		return s, ok2
	})(); ok {
		service.LogOperation(h.db, uidStr, "delete_post", "post", id, nil)
	}
	// Notify author
	reason := strings.TrimSpace(c.Query("reason"))
	if reason == "" {
		reason = "管理员删除了该帖子，内容已从系统中移除。"
	}
	content := h.buildPostNotificationContent("帖子被删除", &p, operator, reason)
	service.Notify(h.db, p.AuthorID, "帖子被删除", content, map[string]any{"post_id": p.ID})
	basichttp.OK(c, gin.H{"id": id, "deleted": true})
}

// ListModeration lists posts for admins, including hidden and deleted ones.
// GET /api/posts/moderation (auth; requires any of MANAGE_POSTS or superadmin)
// query: status (0/1/2), author_id, featured=true, pinned=true, page, page_size
func (h *PostHandler) ListModeration(c *gin.Context) {
	// Permission check: allow superadmin or user having any of the post management permissions
	if !mw.IsSuper(c, h.db) {
		uid, _ := c.Get(mw.CtxUserID)
		var cnt int64
		h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL",
			uid, "MANAGE_POSTS").Scan(&cnt)
		if cnt == 0 {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
			return
		}
	}

	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}
	dbq := h.db.Model(&model.Post{}).Where("deleted_at IS NULL")

	if v := c.Query("status"); v != "" {
		dbq = dbq.Where("status = ?", v)
	}
	if v := c.Query("author_id"); v != "" {
		dbq = dbq.Where("author_id = ?", v)
	}
	if v := c.Query("featured"); v == "true" {
		dbq = dbq.Where("is_featured = 1")
	}
	if v := c.Query("pinned"); v == "true" {
		dbq = dbq.Where("is_pinned = 1")
	}

	var total int64
	dbq.Count(&total)
	var items []model.Post
	if err := dbq.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": h.enrichPostsWithUserTags(items), "page": page, "page_size": size})
}

// Restore sets a deleted post (status=2) back to visible (status=0)
// POST /api/posts/:id/restore (auth; requires MANAGE_POSTS or superadmin)
func (h *PostHandler) Restore(c *gin.Context) {
	id := c.Param("id")
	// Permission: MANAGE_POSTS or superadmin
	if !mw.IsSuper(c, h.db) {
		uid, _ := c.Get(mw.CtxUserID)
		var cnt int64
		h.db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id=? AND permission=? AND deleted_at IS NULL", uid, "MANAGE_POSTS").Scan(&cnt)
		if cnt == 0 {
			basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "no permission")
			return
		}
	}

	var p model.Post
	if err := h.db.First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	if p.Status != 2 {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "post is not deleted")
		return
	}
	if err := h.db.Model(&model.Post{}).Where("id = ?", id).Update("status", 0).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "restore failed")
		return
	}
	if uid, ok := c.Get(mw.CtxUserID); ok {
		if uidStr, ok2 := uid.(string); ok2 {
			service.LogOperation(h.db, uidStr, "restore_post", "post", id, nil)
		}
	}
	basichttp.OK(c, gin.H{"id": id, "status": 0})
}

func (h *PostHandler) resolveOperatorName(c *gin.Context) string {
	uidVal, ok := c.Get(mw.CtxUserID)
	if !ok {
		return "系统"
	}
	uidStr, ok := uidVal.(string)
	if !ok || strings.TrimSpace(uidStr) == "" {
		return "系统"
	}
	if name := h.getUserDisplayName(uidStr); strings.TrimSpace(name) != "" {
		return name
	}
	return uidStr
}

func (h *PostHandler) pickReason(reasonPtr *string) string {
	if reasonPtr == nil {
		return ""
	}
	return strings.TrimSpace(*reasonPtr)
}

func (h *PostHandler) buildPostNotificationContent(actionTitle string, post *model.Post, operatorName, reason string) string {
	operatorName = ensureText(operatorName, "系统")
	reason = ensureText(reason, "（未提供原因）")
	targetName := ensureText(post.TargetName, "（未填写）")
	authorDisplay := ensureText(h.computeAuthorDisplayName(post), "（未填写）")
	body := ensureText(post.Content, "（无正文内容）")

	return fmt.Sprintf(`<div class="notification-card">
  <h3>%s</h3>
  <p><strong>处理人：</strong>%s</p>
  <p><strong>帖子 ID：</strong>%s</p>
  <p><strong>表白对象：</strong>%s</p>
  <p><strong>发布者：</strong>%s</p>
  <p><strong>处理原因：</strong>%s</p>
  <div class="post-preview">
    <div class="post-preview__label">原始内容</div>
    <pre class="post-preview__body" style="white-space: pre-wrap;">%s</pre>
  </div>
</div>`,
		html.EscapeString(actionTitle),
		html.EscapeString(operatorName),
		html.EscapeString(post.ID),
		html.EscapeString(targetName),
		html.EscapeString(authorDisplay),
		html.EscapeString(reason),
		html.EscapeString(body),
	)
}

func (h *PostHandler) buildManualReviewNotificationContent(post *model.Post, requesterName, aiAdvice string) string {
	requesterName = ensureText(requesterName, "用户")
	aiAdvice = ensureText(aiAdvice, "（AI 未提供建议）")
	targetName := ensureText(post.TargetName, "（未填写）")
	authorDisplay := ensureText(h.computeAuthorDisplayName(post), "（未填写）")
	body := ensureText(post.Content, "（无正文内容）")

	return fmt.Sprintf(`<div class="notification-card notification-card--review">
  <h3>收到人工复核申请</h3>
  <p><strong>申请人：</strong>%s</p>
  <p><strong>帖子 ID：</strong>%s</p>
  <p><strong>发布者：</strong>%s</p>
  <p><strong>表白对象：</strong>%s</p>
  <div class="post-preview">
    <div class="post-preview__label">原始内容</div>
    <pre class="post-preview__body" style="white-space: pre-wrap;">%s</pre>
  </div>
  <div class="post-review-ai">
    <div class="post-review-ai__label">AI 建议</div>
    <pre class="post-review-ai__body" style="white-space: pre-wrap;">%s</pre>
  </div>
</div>`,
		html.EscapeString(requesterName),
		html.EscapeString(post.ID),
		html.EscapeString(authorDisplay),
		html.EscapeString(targetName),
		html.EscapeString(body),
		html.EscapeString(aiAdvice),
	)
}

func ensureText(val, fallback string) string {
	if strings.TrimSpace(val) == "" {
		return fallback
	}
	return val
}
