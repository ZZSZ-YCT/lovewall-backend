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
	Content       string `form:"content" json:"content"`
	ConfessorMode string `form:"confessor_mode" json:"confessor_mode"` // optional: "self" or "custom"
	CardType      string `form:"card_type" json:"card_type"`
	ReplyToID     string `form:"reply_to_id" json:"reply_to_id"`
	RepostOfID    string `form:"repost_of_id" json:"repost_of_id"`
	QuoteOfID     string `form:"quote_of_id" json:"quote_of_id"`
}

func (h *PostHandler) CreatePost(c *gin.Context) {
	var form CreatePostForm
	if err := c.ShouldBind(&form); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid form")
		return
	}

	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	// Determine post type: repost, quote, reply, or original
	isRepost := strings.TrimSpace(form.RepostOfID) != ""
	isQuote := strings.TrimSpace(form.QuoteOfID) != ""
	isReply := strings.TrimSpace(form.ReplyToID) != ""

	// Validate: cannot be multiple types at once
	typeCount := 0
	if isRepost {
		typeCount++
	}
	if isQuote {
		typeCount++
	}
	if isReply {
		typeCount++
	}
	if typeCount > 1 {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "post can only be one of: reply, repost, or quote")
		return
	}

	// Repost: no content allowed
	if isRepost && strings.TrimSpace(form.Content) != "" {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "repost cannot have content")
		return
	}
	// Quote: content required
	if isQuote && strings.TrimSpace(form.Content) == "" {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "quote must have content")
		return
	}
	// Original/reply: content required
	if !isRepost && strings.TrimSpace(form.Content) == "" {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "content is required")
		return
	}

	// Validate target post exists for repost/quote/reply
	var replyToID, repostOfID, quoteOfID *string
	if isReply {
		var target model.Post
		if err := h.db.First(&target, "id = ? AND deleted_at IS NULL", strings.TrimSpace(form.ReplyToID)).Error; err != nil {
			basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "reply target post not found")
			return
		}
		if target.Status != 0 {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "cannot reply to hidden post")
			return
		}
		id := strings.TrimSpace(form.ReplyToID)
		replyToID = &id
	}
	if isRepost {
		var target model.Post
		if err := h.db.First(&target, "id = ? AND deleted_at IS NULL AND status = 0", strings.TrimSpace(form.RepostOfID)).Error; err != nil {
			basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "repost target not found")
			return
		}
		id := strings.TrimSpace(form.RepostOfID)
		repostOfID = &id
	}
	if isQuote {
		var target model.Post
		if err := h.db.First(&target, "id = ? AND deleted_at IS NULL AND status = 0", strings.TrimSpace(form.QuoteOfID)).Error; err != nil {
			basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "quote target not found")
			return
		}
		id := strings.TrimSpace(form.QuoteOfID)
		quoteOfID = &id
	}

	cardType := strings.ToLower(strings.TrimSpace(form.CardType))
	if cardType == "" {
		if isReply || isRepost || isQuote {
			cardType = "social"
		} else {
			cardType = "confession"
		}
	}
	if cardType != "confession" && cardType != "social" {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid card_type")
		return
	}
	targetName := strings.TrimSpace(form.TargetName)
	if cardType == "confession" && targetName == "" && !isReply && !isRepost && !isQuote {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "target_name is required for confession cards")
		return
	}

	// Handle multiple images: up to 9 images, each <= 5MB
	const maxImages = 9
	const perFileLimitBytes int64 = 5 * 1024 * 1024
	imageURLs := make([]string, 0)
	if !isRepost { // reposts don't have images
		if formdata, err := c.MultipartForm(); err == nil && formdata != nil {
			files := formdata.File["images"]
			if len(files) == 0 {
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
	}

	// Determine confessor mode and author name
	mode := strings.ToLower(strings.TrimSpace(form.ConfessorMode))
	if mode == "" {
		if isReply || isRepost || isQuote {
			mode = "self"
		} else {
			mode = "custom"
		}
	}
	var authorName string
	if mode == "self" {
		authorName = h.getUserDisplayName(uidStr)
		if strings.TrimSpace(authorName) == "" {
			authorName = ""
		}
	} else {
		authorName = strings.TrimSpace(form.AuthorName)
		if authorName == "" && !isReply && !isRepost && !isQuote {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "author_name is required when confessor_mode is custom")
			return
		}
		mode = "custom"
	}

	// Length validation
	if !isRepost {
		if len([]rune(form.Content)) > 1000 {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "内容长度超过1000字")
			return
		}
		if len([]rune(form.Content)) > h.cfg.MaxPostChars {
			basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", fmt.Sprintf("内容长度超过限制(%d)", h.cfg.MaxPostChars))
			return
		}
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
		AuthorID:      uidStr,
		AuthorName:    authorName,
		TargetName:    targetName,
		Content:       form.Content,
		Status:        1,
		IsPinned:      false,
		IsFeatured:    false,
		ConfessorMode: &mode,
		CardType:      &cardType,
		AuditStatus:   1,
		AuditMsg:      nil,
		ReplyToID:     replyToID,
		RepostOfID:    repostOfID,
		QuoteOfID:     quoteOfID,
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
		_ = h.db.Create(&imgs).Error
	}
	// Note: repost_count and quote_count will be incremented when the post is approved
	// Parse @mentions and create records
	if !isRepost && strings.TrimSpace(form.Content) != "" {
		service.CreateMentions(h.db, p.ID, uidStr, form.Content)
	}
	// Notify reply target author
	if isReply {
		var parentPost model.Post
		if err := h.db.Select("author_id").First(&parentPost, "id = ?", *replyToID).Error; err == nil {
			if parentPost.AuthorID != uidStr {
				service.Notify(h.db, parentPost.AuthorID, "有人回复了你的帖子", "你的帖子收到了新回复，点击查看。", map[string]any{
					"post_id":  *replyToID,
					"reply_id": p.ID,
					"type":     "reply",
				})
			}
		}
	}
	// Log submission
	service.LogSubmission(h.db, uidStr, "post_create", "post", p.ID, map[string]any{"target_name": p.TargetName, "ip": c.ClientIP()})
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

	feed := strings.TrimSpace(c.Query("feed"))

	// Base query: only top-level posts (not replies, not reposts)
	q := h.db.Model(&model.Post{}).Where("status = 0 AND deleted_at IS NULL AND reply_to_id IS NULL AND repost_of_id IS NULL")

	// Feed filtering (requires auth)
	if feed == "following" || feed == "recommended" {
		uid, exists := c.Get(mw.CtxUserID)
		if !exists {
			basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required for feed filtering")
			return
		}
		uidStr := uid.(string)

		// Get blocked user IDs
		var blockedIDs []string
		h.db.Model(&model.UserBlock{}).
			Where("blocker_id = ? AND deleted_at IS NULL", uidStr).
			Pluck("blocked_id", &blockedIDs)

		// Exclude posts from blocked users
		if len(blockedIDs) > 0 {
			q = q.Where("author_id NOT IN ?", blockedIDs)
		}

		if feed == "following" {
			// Following feed: posts from users I follow
			var followingIDs []string
			h.db.Model(&model.UserFollow{}).
				Where("follower_id = ? AND deleted_at IS NULL", uidStr).
				Pluck("following_id", &followingIDs)
			if len(followingIDs) == 0 {
				// No following, return empty
				basichttp.OK(c, gin.H{"total": 0, "items": []gin.H{}, "page": page, "page_size": size})
				return
			}
			q = q.Where("author_id IN ?", followingIDs)
		}
		// "recommended" = all posts (excluding blocked), no additional filter
	}

	if v := c.Query("featured"); v == "true" {
		q = q.Where("is_featured = ?", true)
	}
	if v := c.Query("pinned"); v == "true" {
		q = q.Where("is_pinned = ?", true)
	}
	q.Count(&total)
	// Sort by priority: pinned+featured > pinned > featured > normal, then by time
	q = q.Order("is_pinned DESC, is_featured DESC, created_at DESC").Offset((page - 1) * size).Limit(size)
	if err := q.Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{
		"total":     total,
		"items":     h.enrichPostsWithUserTagsCtx(items, c),
		"page":      page,
		"page_size": size,
	})
}

// GET /api/users/:id/posts (public)
// Lists visible posts authored by the specified user.
// Query param: type=posts|replies|reposts|likes (default: all original posts)
func (h *PostHandler) ListByUser(c *gin.Context) {
	userID := c.Param("id")
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	postType := strings.TrimSpace(c.Query("type"))

	var total int64
	var items []model.Post

	switch postType {
	case "replies":
		q := h.db.Model(&model.Post{}).
			Where("author_id = ? AND status = 0 AND deleted_at IS NULL AND reply_to_id IS NOT NULL", userID)
		q.Count(&total)
		if err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
			return
		}
	case "reposts":
		q := h.db.Model(&model.Post{}).
			Where("author_id = ? AND status = 0 AND deleted_at IS NULL AND repost_of_id IS NOT NULL", userID)
		q.Count(&total)
		if err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
			return
		}
	case "likes":
		// Return posts that this user has liked
		q := h.db.Model(&model.Post{}).
			Joins("JOIN post_likes ON post_likes.post_id = posts.id AND post_likes.deleted_at IS NULL").
			Where("post_likes.user_id = ? AND posts.status = 0 AND posts.deleted_at IS NULL", userID)
		q.Count(&total)
		if err := q.Order("post_likes.created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
			return
		}
	case "posts":
		// Only original posts (no replies, no reposts)
		q := h.db.Model(&model.Post{}).
			Where("author_id = ? AND status = 0 AND deleted_at IS NULL AND reply_to_id IS NULL AND repost_of_id IS NULL", userID)
		q.Count(&total)
		if err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
			return
		}
	default:
		// All posts by user (original + quotes, excluding replies and reposts)
		q := h.db.Model(&model.Post{}).
			Where("author_id = ? AND status = 0 AND deleted_at IS NULL AND reply_to_id IS NULL AND repost_of_id IS NULL", userID)
		q.Count(&total)
		if err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
			return
		}
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
	items := h.enrichPostsWithUserTagsCtx([]model.Post{p}, c)
	if len(items) > 0 {
		basichttp.OK(c, items[0])
	} else {
		basichttp.OK(c, h.enrichPostWithUserTag(&p))
	}
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
	return h.enrichPostsWithUserTagsCtx(posts, nil)
}

// enrichPostsWithUserTagsCtx enriches posts with user tags and optionally checks like status.
func (h *PostHandler) enrichPostsWithUserTagsCtx(posts []model.Post, c *gin.Context) []gin.H {
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

	// Batch query related posts (reply_to, repost_of, quote_of)
	relatedIDs := make([]string, 0)
	relatedIDSet := make(map[string]struct{})
	for i := range posts {
		for _, ptr := range []*string{posts[i].ReplyToID, posts[i].RepostOfID, posts[i].QuoteOfID} {
			if ptr != nil && *ptr != "" {
				if _, ok := relatedIDSet[*ptr]; !ok {
					relatedIDSet[*ptr] = struct{}{}
					relatedIDs = append(relatedIDs, *ptr)
				}
			}
		}
	}
	relatedPostMap := make(map[string]*model.Post)
	if len(relatedIDs) > 0 {
		var relatedPosts []model.Post
		if err := h.db.Where("id IN ?", relatedIDs).Find(&relatedPosts).Error; err == nil {
			for i := range relatedPosts {
				relatedPostMap[relatedPosts[i].ID] = &relatedPosts[i]
			}
		}
		// Also fetch user info for related post authors
		relatedAuthorIDs := make([]string, 0)
		for _, rp := range relatedPostMap {
			if !authorIDSet[rp.AuthorID] {
				relatedAuthorIDs = append(relatedAuthorIDs, rp.AuthorID)
				authorIDSet[rp.AuthorID] = true
			}
		}
		if len(relatedAuthorIDs) > 0 {
			var relatedUsers []model.User
			if err := h.db.Select("id, username, display_name, avatar_url").
				Where("id IN ? AND deleted_at IS NULL", relatedAuthorIDs).
				Find(&relatedUsers).Error; err == nil {
				for i := range relatedUsers {
					userMap[relatedUsers[i].ID] = &relatedUsers[i]
				}
			}
		}
	}

	// Batch query mentions
	mentionMap := make(map[string][]gin.H)
	if len(postIDs) > 0 {
		var mentions []model.PostMention
		if err := h.db.Where("post_id IN ?", postIDs).Find(&mentions).Error; err == nil {
			for _, m := range mentions {
				mentionMap[m.PostID] = append(mentionMap[m.PostID], gin.H{
					"user_id":  m.MentionedUserID,
					"username": m.Username,
				})
			}
		}
	}

	// Batch query liked_by_me if user is logged in
	likedByMe := make(map[string]bool)
	if c != nil {
		if uid, exists := c.Get(mw.CtxUserID); exists {
			if uidStr, ok := uid.(string); ok && uidStr != "" {
				var likedPostIDs []string
				h.db.Model(&model.PostLike{}).
					Where("user_id = ? AND post_id IN ? AND deleted_at IS NULL", uidStr, postIDs).
					Pluck("post_id", &likedPostIDs)
				for _, pid := range likedPostIDs {
					likedByMe[pid] = true
				}
			}
		}
	}

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
			"like_count":              post.LikeCount,
			"repost_count":            post.RepostCount,
			"quote_count":             post.QuoteCount,
			"reply_count":             post.ReplyCount,
			"reply_to_id":             post.ReplyToID,
			"repost_of_id":            post.RepostOfID,
			"quote_of_id":             post.QuoteOfID,
			"audit_status":            post.AuditStatus,
			"audit_msg":               post.AuditMsg,
			"manual_review_requested": post.ManualReviewRequested,
			"is_pending_review":       post.AuditStatus == 1,
			"mentions":                mentionMap[post.ID],
			"liked_by_me":             likedByMe[post.ID],
		}

		// Add related post summaries
		if post.ReplyToID != nil {
			if rp, ok := relatedPostMap[*post.ReplyToID]; ok {
				summary := h.buildPostSummary(rp, userMap)
				item["reply_to"] = summary
			}
		}
		if post.RepostOfID != nil {
			if rp, ok := relatedPostMap[*post.RepostOfID]; ok {
				summary := h.buildPostSummary(rp, userMap)
				item["repost_of"] = summary
			}
		}
		if post.QuoteOfID != nil {
			if rp, ok := relatedPostMap[*post.QuoteOfID]; ok {
				summary := h.buildPostSummary(rp, userMap)
				item["quote_of"] = summary
			}
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

// buildPostSummary creates a lightweight summary of a related post.
func (h *PostHandler) buildPostSummary(post *model.Post, userMap map[string]*model.User) gin.H {
	if post == nil {
		return nil
	}
	contentPreview := post.Content
	if len([]rune(contentPreview)) > 200 {
		contentPreview = string([]rune(contentPreview)[:200]) + "..."
	}
	summary := gin.H{
		"id":          post.ID,
		"author_id":   post.AuthorID,
		"author_name": post.AuthorName,
		"content":     contentPreview,
		"created_at":  post.CreatedAt,
	}
	if user, ok := userMap[post.AuthorID]; ok {
		if user.DisplayName != nil && *user.DisplayName != "" {
			summary["author_display_name"] = *user.DisplayName
		} else {
			summary["author_display_name"] = user.Username
		}
		summary["author_avatar_url"] = user.AvatarURL
		summary["author_username"] = user.Username
	}
	return summary
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
	if err := h.db.Select("id, view_count, comment_count, like_count, repost_count, quote_count, reply_count").First(&p, "id = ? AND deleted_at IS NULL", id).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}
	basichttp.OK(c, gin.H{
		"id":            p.ID,
		"view_count":    p.ViewCount,
		"comment_count": p.CommentCount,
		"like_count":    p.LikeCount,
		"repost_count":  p.RepostCount,
		"quote_count":   p.QuoteCount,
		"reply_count":   p.ReplyCount,
	})
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

	oldStatus := p.Status

	tx := h.db.Begin()
	if tx.Error != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "transaction failed")
		return
	}

	if err := tx.Model(&model.Post{}).Where("id = ?", id).Update("status", newStatus).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}

	// Update parent counts based on status change
	// If hiding (0->1): decrement counts
	// If unhiding (1->0): increment counts
	if oldStatus == 0 && newStatus == 1 {
		// Hiding: decrement counts
		if p.ReplyToID != nil && *p.ReplyToID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.ReplyToID).Update("reply_count", gorm.Expr("CASE WHEN reply_count > 0 THEN reply_count - 1 ELSE 0 END")).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
				return
			}
		}
		if p.RepostOfID != nil && *p.RepostOfID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.RepostOfID).Update("repost_count", gorm.Expr("CASE WHEN repost_count > 0 THEN repost_count - 1 ELSE 0 END")).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
				return
			}
		}
		if p.QuoteOfID != nil && *p.QuoteOfID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.QuoteOfID).Update("quote_count", gorm.Expr("CASE WHEN quote_count > 0 THEN quote_count - 1 ELSE 0 END")).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
				return
			}
		}
	} else if oldStatus == 1 && newStatus == 0 {
		// Unhiding: increment counts
		if p.ReplyToID != nil && *p.ReplyToID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.ReplyToID).Update("reply_count", gorm.Expr("reply_count + 1")).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
				return
			}
		}
		if p.RepostOfID != nil && *p.RepostOfID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.RepostOfID).Update("repost_count", gorm.Expr("repost_count + 1")).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
				return
			}
		}
		if p.QuoteOfID != nil && *p.QuoteOfID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.QuoteOfID).Update("quote_count", gorm.Expr("quote_count + 1")).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
				return
			}
		}
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
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

	wasVisible := p.Status == 0

	tx := h.db.Begin()
	if tx.Error != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "transaction failed")
		return
	}

	// Apply updates and set pending moderation again
	updates["status"] = 1
	updates["audit_status"] = 1
	updates["audit_msg"] = nil
	updates["manual_review_requested"] = false
	if err := tx.Model(&model.Post{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update failed")
		return
	}

	// If post was visible and is now pending review, decrement parent counts
	if wasVisible {
		if p.ReplyToID != nil && *p.ReplyToID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.ReplyToID).Update("reply_count", gorm.Expr("CASE WHEN reply_count > 0 THEN reply_count - 1 ELSE 0 END")).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
				return
			}
		}
		if p.RepostOfID != nil && *p.RepostOfID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.RepostOfID).Update("repost_count", gorm.Expr("CASE WHEN repost_count > 0 THEN repost_count - 1 ELSE 0 END")).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
				return
			}
		}
		if p.QuoteOfID != nil && *p.QuoteOfID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.QuoteOfID).Update("quote_count", gorm.Expr("CASE WHEN quote_count > 0 THEN quote_count - 1 ELSE 0 END")).Error; err != nil {
				tx.Rollback()
				basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
				return
			}
		}
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
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
	// Hard delete: remove post and its comments, images, likes, mentions in a transaction
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
	if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.PostLike{}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.PostMention{}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.PostView{}).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "delete failed")
		return
	}
	// Decrement parent reply_count if this was a reply
	if p.ReplyToID != nil && *p.ReplyToID != "" && p.Status == 0 {
		if err := tx.Model(&model.Post{}).Where("id = ?", *p.ReplyToID).Update("reply_count", gorm.Expr("CASE WHEN reply_count > 0 THEN reply_count - 1 ELSE 0 END")).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
			return
		}
	}
	// Decrement repost/quote counts (only if post was visible)
	if p.RepostOfID != nil && *p.RepostOfID != "" && p.Status == 0 {
		if err := tx.Model(&model.Post{}).Where("id = ?", *p.RepostOfID).Update("repost_count", gorm.Expr("CASE WHEN repost_count > 0 THEN repost_count - 1 ELSE 0 END")).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
			return
		}
	}
	if p.QuoteOfID != nil && *p.QuoteOfID != "" && p.Status == 0 {
		if err := tx.Model(&model.Post{}).Where("id = ?", *p.QuoteOfID).Update("quote_count", gorm.Expr("CASE WHEN quote_count > 0 THEN quote_count - 1 ELSE 0 END")).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
			return
		}
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
		dbq = dbq.Where("is_featured = ?", true)
	}
	if v := c.Query("pinned"); v == "true" {
		dbq = dbq.Where("is_pinned = ?", true)
	}

	var total int64
	dbq.Count(&total)
	var items []model.Post
	// Moderation queue shows latest activity first (no priority sorting)
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

// ===== X-style new endpoints =====

// GET /api/posts/:id/replies (public)
// Returns direct replies to a post.
func (h *PostHandler) ListReplies(c *gin.Context) {
	postID := c.Param("id")
	// Ensure parent post exists
	var parent model.Post
	if err := h.db.First(&parent, "id = ? AND deleted_at IS NULL", postID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}

	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	var items []model.Post
	q := h.db.Model(&model.Post{}).
		Where("reply_to_id = ? AND status = 0 AND deleted_at IS NULL", postID)
	q.Count(&total)
	if err := q.Order("created_at ASC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": h.enrichPostsWithUserTagsCtx(items, c), "page": page, "page_size": size})
}

// GET /api/posts/:id/thread (public)
// Returns the full conversation thread by walking up the reply chain.
func (h *PostHandler) GetThread(c *gin.Context) {
	postID := c.Param("id")
	var current model.Post
	if err := h.db.First(&current, "id = ? AND deleted_at IS NULL", postID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}

	// Walk up the reply chain (max 50 levels)
	chain := []model.Post{current}
	visited := map[string]bool{current.ID: true}
	cursor := &current
	for i := 0; i < 50; i++ {
		if cursor.ReplyToID == nil || *cursor.ReplyToID == "" {
			break
		}
		if visited[*cursor.ReplyToID] {
			break
		}
		var parent model.Post
		if err := h.db.First(&parent, "id = ? AND deleted_at IS NULL", *cursor.ReplyToID).Error; err != nil {
			break
		}
		visited[parent.ID] = true
		chain = append(chain, parent)
		cursor = &chain[len(chain)-1]
	}

	// Reverse so oldest ancestor is first
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	basichttp.OK(c, gin.H{
		"thread": h.enrichPostsWithUserTagsCtx(chain, c),
		"count":  len(chain),
	})
}

// POST /api/posts/:id/like (auth)
func (h *PostHandler) LikePost(c *gin.Context) {
	postID := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	var p model.Post
	if err := h.db.First(&p, "id = ? AND deleted_at IS NULL AND status = 0", postID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "post not found")
		return
	}

	// Check if already liked
	var existing model.PostLike
	if err := h.db.Where("user_id = ? AND post_id = ? AND deleted_at IS NULL", uidStr, postID).First(&existing).Error; err == nil {
		basichttp.OK(c, gin.H{"liked": true, "message": "already liked"})
		return
	}

	tx := h.db.Begin()
	if tx.Error != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "transaction failed")
		return
	}

	like := &model.PostLike{UserID: uidStr, PostID: postID}
	if err := tx.Create(like).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "like failed")
		return
	}
	if err := tx.Model(&model.Post{}).Where("id = ?", postID).Update("like_count", gorm.Expr("like_count + 1")).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
		return
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}

	// Notify post author
	if p.AuthorID != uidStr {
		service.Notify(h.db, p.AuthorID, "有人点赞了你的帖子", "你的帖子收到了一个赞。", map[string]any{
			"post_id": postID,
			"liker":   uidStr,
			"type":    "like",
		})
	}

	basichttp.OK(c, gin.H{"liked": true})
}

// DELETE /api/posts/:id/like (auth)
func (h *PostHandler) UnlikePost(c *gin.Context) {
	postID := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	tx := h.db.Begin()
	if tx.Error != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "transaction failed")
		return
	}

	result := tx.Unscoped().Where("user_id = ? AND post_id = ?", uidStr, postID).Delete(&model.PostLike{})
	if result.Error != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "unlike failed")
		return
	}
	if result.RowsAffected > 0 {
		if err := tx.Model(&model.Post{}).Where("id = ?", postID).Update("like_count", gorm.Expr("CASE WHEN like_count > 0 THEN like_count - 1 ELSE 0 END")).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
			return
		}
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}

	basichttp.OK(c, gin.H{"liked": false})
}

// GET /api/posts/:id/likes (public)
func (h *PostHandler) ListLikes(c *gin.Context) {
	postID := c.Param("id")
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	h.db.Model(&model.PostLike{}).Where("post_id = ? AND deleted_at IS NULL", postID).Count(&total)

	var likes []model.PostLike
	if err := h.db.Where("post_id = ? AND deleted_at IS NULL", postID).
		Order("created_at DESC").Offset((page - 1) * size).Limit(size).
		Find(&likes).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}

	userIDs := make([]string, len(likes))
	for i, l := range likes {
		userIDs[i] = l.UserID
	}

	userMap := make(map[string]*model.User)
	if len(userIDs) > 0 {
		var users []model.User
		h.db.Select("id, username, display_name, avatar_url").
			Where("id IN ? AND deleted_at IS NULL", userIDs).Find(&users)
		for i := range users {
			userMap[users[i].ID] = &users[i]
		}
	}

	items := make([]gin.H, 0, len(likes))
	for _, l := range likes {
		item := gin.H{"user_id": l.UserID, "liked_at": l.CreatedAt}
		if u, ok := userMap[l.UserID]; ok {
			item["username"] = u.Username
			if u.DisplayName != nil {
				item["display_name"] = *u.DisplayName
			}
			item["avatar_url"] = u.AvatarURL
		}
		items = append(items, item)
	}

	basichttp.OK(c, gin.H{"total": total, "items": items, "page": page, "page_size": size})
}

// GET /api/posts/:id/like-status (auth)
func (h *PostHandler) LikeStatus(c *gin.Context) {
	postID := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	var count int64
	h.db.Model(&model.PostLike{}).Where("user_id = ? AND post_id = ? AND deleted_at IS NULL", uidStr, postID).Count(&count)
	basichttp.OK(c, gin.H{"liked": count > 0})
}

// GET /api/my/likes (auth)
func (h *PostHandler) ListMyLikes(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	var items []model.Post
	q := h.db.Model(&model.Post{}).
		Joins("JOIN post_likes ON post_likes.post_id = posts.id AND post_likes.deleted_at IS NULL").
		Where("post_likes.user_id = ? AND posts.status = 0 AND posts.deleted_at IS NULL", uidStr)
	q.Count(&total)
	if err := q.Order("post_likes.created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": h.enrichPostsWithUserTagsCtx(items, c), "page": page, "page_size": size})
}

// GET /api/users/by-username/:username/posts (public)
func (h *PostHandler) ListByUsername(c *gin.Context) {
	username := c.Param("username")
	var user model.User
	if err := h.db.Select("id").First(&user, "username = ? AND deleted_at IS NULL", username).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	// Manually call the same logic as ListByUser with the resolved user ID
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}
	postType := strings.TrimSpace(c.Query("type"))
	userID := user.ID

	var total int64
	var items []model.Post

	switch postType {
	case "replies":
		q := h.db.Model(&model.Post{}).
			Where("author_id = ? AND status = 0 AND deleted_at IS NULL AND reply_to_id IS NOT NULL", userID)
		q.Count(&total)
		q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items)
	case "reposts":
		q := h.db.Model(&model.Post{}).
			Where("author_id = ? AND status = 0 AND deleted_at IS NULL AND repost_of_id IS NOT NULL", userID)
		q.Count(&total)
		q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items)
	case "likes":
		q := h.db.Model(&model.Post{}).
			Joins("JOIN post_likes ON post_likes.post_id = posts.id AND post_likes.deleted_at IS NULL").
			Where("post_likes.user_id = ? AND posts.status = 0 AND posts.deleted_at IS NULL", userID)
		q.Count(&total)
		q.Order("post_likes.created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items)
	default:
		q := h.db.Model(&model.Post{}).
			Where("author_id = ? AND status = 0 AND deleted_at IS NULL AND reply_to_id IS NULL AND repost_of_id IS NULL", userID)
		q.Count(&total)
		q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items)
	}

	basichttp.OK(c, gin.H{"total": total, "items": h.enrichPostsWithUserTags(items), "page": page, "page_size": size})
}

// GET /api/users/:id/replies (public)
// Returns user's replies with parent post summaries.
func (h *PostHandler) ListUserReplies(c *gin.Context) {
	userID := c.Param("id")
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	var items []model.Post
	q := h.db.Model(&model.Post{}).
		Where("author_id = ? AND status = 0 AND deleted_at IS NULL AND reply_to_id IS NOT NULL", userID)
	q.Count(&total)
	if err := q.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}
	basichttp.OK(c, gin.H{"total": total, "items": h.enrichPostsWithUserTagsCtx(items, c), "page": page, "page_size": size})
}
