package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lovewall/internal/config"
	basichttp "lovewall/internal/http"
	mw "lovewall/internal/http/middleware"
	"lovewall/internal/model"
	"lovewall/internal/service"
)

type FollowHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewFollowHandler(db *gorm.DB, cfg *config.Config) *FollowHandler {
	return &FollowHandler{db: db, cfg: cfg}
}

// POST /api/users/:id/follow (auth)
func (h *FollowHandler) FollowUser(c *gin.Context) {
	targetUserID := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	if uidStr == targetUserID {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "cannot follow yourself")
		return
	}

	// Verify target user exists
	var targetUser model.User
	if err := h.db.Select("id").First(&targetUser, "id = ? AND deleted_at IS NULL", targetUserID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	// Check if either user has blocked the other
	var blockCount int64
	h.db.Model(&model.UserBlock{}).
		Where("deleted_at IS NULL AND ((blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?))",
			uidStr, targetUserID, targetUserID, uidStr).
		Count(&blockCount)
	if blockCount > 0 {
		basichttp.Fail(c, http.StatusForbidden, "BLOCKED", "cannot follow a blocked user")
		return
	}

	// Check if already following
	var existing model.UserFollow
	if err := h.db.Where("follower_id = ? AND following_id = ? AND deleted_at IS NULL", uidStr, targetUserID).First(&existing).Error; err == nil {
		basichttp.OK(c, gin.H{"following": true, "message": "already following"})
		return
	}

	// Create follow relationship
	follow := &model.UserFollow{FollowerID: uidStr, FollowingID: targetUserID}
	tx := h.db.Begin()
	if tx.Error != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "transaction failed")
		return
	}

	if err := tx.Create(follow).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "follow failed")
		return
	}

	// Update counts
	if err := tx.Model(&model.User{}).Where("id = ?", uidStr).Update("following_count", gorm.Expr("following_count + 1")).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
		return
	}
	if err := tx.Model(&model.User{}).Where("id = ?", targetUserID).Update("follower_count", gorm.Expr("follower_count + 1")).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
		return
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}

	// Notify target user
	service.Notify(h.db, targetUserID, "新增关注者", "有用户关注了你。", map[string]any{
		"follower_id": uidStr,
		"type":        "follow",
	})

	basichttp.OK(c, gin.H{"following": true})
}

// DELETE /api/users/:id/follow (auth)
func (h *FollowHandler) UnfollowUser(c *gin.Context) {
	targetUserID := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	tx := h.db.Begin()
	if tx.Error != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "transaction failed")
		return
	}

	result := tx.Unscoped().Where("follower_id = ? AND following_id = ?", uidStr, targetUserID).Delete(&model.UserFollow{})
	if result.Error != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "unfollow failed")
		return
	}
	if result.RowsAffected > 0 {
		if err := tx.Model(&model.User{}).Where("id = ?", uidStr).Update("following_count", gorm.Expr("CASE WHEN following_count > 0 THEN following_count - 1 ELSE 0 END")).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
			return
		}
		if err := tx.Model(&model.User{}).Where("id = ?", targetUserID).Update("follower_count", gorm.Expr("CASE WHEN follower_count > 0 THEN follower_count - 1 ELSE 0 END")).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
			return
		}
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}

	basichttp.OK(c, gin.H{"following": false})
}

// GET /api/users/:id/followers (public)
func (h *FollowHandler) ListFollowers(c *gin.Context) {
	userID := c.Param("id")
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	h.db.Model(&model.UserFollow{}).Where("following_id = ? AND deleted_at IS NULL", userID).Count(&total)

	var follows []model.UserFollow
	if err := h.db.Where("following_id = ? AND deleted_at IS NULL", userID).
		Order("created_at DESC").Offset((page - 1) * size).Limit(size).
		Find(&follows).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}

	followerIDs := make([]string, len(follows))
	for i, f := range follows {
		followerIDs[i] = f.FollowerID
	}

	userMap := make(map[string]*model.User)
	if len(followerIDs) > 0 {
		var users []model.User
		h.db.Select("id, username, display_name, avatar_url").
			Where("id IN ? AND deleted_at IS NULL", followerIDs).Find(&users)
		for i := range users {
			userMap[users[i].ID] = &users[i]
		}
	}

	items := make([]gin.H, 0, len(follows))
	for _, f := range follows {
		item := gin.H{"user_id": f.FollowerID, "followed_at": f.CreatedAt}
		if u, ok := userMap[f.FollowerID]; ok {
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

// GET /api/users/:id/following (public)
func (h *FollowHandler) ListFollowing(c *gin.Context) {
	userID := c.Param("id")
	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	h.db.Model(&model.UserFollow{}).Where("follower_id = ? AND deleted_at IS NULL", userID).Count(&total)

	var follows []model.UserFollow
	if err := h.db.Where("follower_id = ? AND deleted_at IS NULL", userID).
		Order("created_at DESC").Offset((page - 1) * size).Limit(size).
		Find(&follows).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}

	followingIDs := make([]string, len(follows))
	for i, f := range follows {
		followingIDs[i] = f.FollowingID
	}

	userMap := make(map[string]*model.User)
	if len(followingIDs) > 0 {
		var users []model.User
		h.db.Select("id, username, display_name, avatar_url").
			Where("id IN ? AND deleted_at IS NULL", followingIDs).Find(&users)
		for i := range users {
			userMap[users[i].ID] = &users[i]
		}
	}

	items := make([]gin.H, 0, len(follows))
	for _, f := range follows {
		item := gin.H{"user_id": f.FollowingID, "followed_at": f.CreatedAt}
		if u, ok := userMap[f.FollowingID]; ok {
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

// GET /api/users/:id/follow-status (auth)
func (h *FollowHandler) FollowStatus(c *gin.Context) {
	targetUserID := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	var count int64
	h.db.Model(&model.UserFollow{}).Where("follower_id = ? AND following_id = ? AND deleted_at IS NULL", uidStr, targetUserID).Count(&count)
	basichttp.OK(c, gin.H{"following": count > 0})
}

// POST /api/users/:id/block (auth)
func (h *FollowHandler) BlockUser(c *gin.Context) {
	targetUserID := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	if uidStr == targetUserID {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "cannot block yourself")
		return
	}

	// Verify target user exists
	var targetUser model.User
	if err := h.db.Select("id").First(&targetUser, "id = ? AND deleted_at IS NULL", targetUserID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	// Check if already blocked
	var existing model.UserBlock
	if err := h.db.Where("blocker_id = ? AND blocked_id = ? AND deleted_at IS NULL", uidStr, targetUserID).First(&existing).Error; err == nil {
		basichttp.OK(c, gin.H{"blocked": true, "message": "already blocked"})
		return
	}

	// Use transaction to ensure atomicity
	tx := h.db.Begin()
	if tx.Error != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "transaction failed")
		return
	}

	// Create block relationship
	block := &model.UserBlock{BlockerID: uidStr, BlockedID: targetUserID}
	if err := tx.Create(block).Error; err != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "block failed")
		return
	}

	// Remove follow relationship: I follow target
	res1 := tx.Unscoped().Where("follower_id = ? AND following_id = ?", uidStr, targetUserID).Delete(&model.UserFollow{})
	if res1.Error != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "cleanup failed")
		return
	}
	if res1.RowsAffected > 0 {
		if err := tx.Model(&model.User{}).Where("id = ?", uidStr).Update("following_count", gorm.Expr("CASE WHEN following_count > 0 THEN following_count - 1 ELSE 0 END")).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
			return
		}
		if err := tx.Model(&model.User{}).Where("id = ?", targetUserID).Update("follower_count", gorm.Expr("CASE WHEN follower_count > 0 THEN follower_count - 1 ELSE 0 END")).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
			return
		}
	}

	// Remove follow relationship: target follows me
	res2 := tx.Unscoped().Where("follower_id = ? AND following_id = ?", targetUserID, uidStr).Delete(&model.UserFollow{})
	if res2.Error != nil {
		tx.Rollback()
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "cleanup failed")
		return
	}
	if res2.RowsAffected > 0 {
		if err := tx.Model(&model.User{}).Where("id = ?", targetUserID).Update("following_count", gorm.Expr("CASE WHEN following_count > 0 THEN following_count - 1 ELSE 0 END")).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
			return
		}
		if err := tx.Model(&model.User{}).Where("id = ?", uidStr).Update("follower_count", gorm.Expr("CASE WHEN follower_count > 0 THEN follower_count - 1 ELSE 0 END")).Error; err != nil {
			tx.Rollback()
			basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "update count failed")
			return
		}
	}

	if err := tx.Commit().Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "commit failed")
		return
	}

	basichttp.OK(c, gin.H{"blocked": true})
}

// DELETE /api/users/:id/block (auth)
func (h *FollowHandler) UnblockUser(c *gin.Context) {
	targetUserID := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	result := h.db.Unscoped().Where("blocker_id = ? AND blocked_id = ?", uidStr, targetUserID).Delete(&model.UserBlock{})
	_ = result.Error
	basichttp.OK(c, gin.H{"blocked": false})
}

// GET /api/users/:id/blocks (auth, owner only)
func (h *FollowHandler) ListBlocks(c *gin.Context) {
	userID := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	// Only allow users to view their own block list
	if uidStr != userID {
		basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "can only view your own blocks")
		return
	}

	page := queryInt(c, "page", 1)
	size := queryInt(c, "page_size", 20)
	if size > 100 {
		size = 100
	}

	var total int64
	h.db.Model(&model.UserBlock{}).Where("blocker_id = ? AND deleted_at IS NULL", userID).Count(&total)

	var blocks []model.UserBlock
	if err := h.db.Where("blocker_id = ? AND deleted_at IS NULL", userID).
		Order("created_at DESC").Offset((page - 1) * size).Limit(size).
		Find(&blocks).Error; err != nil {
		basichttp.Fail(c, http.StatusInternalServerError, "INTERNAL_ERROR", "query failed")
		return
	}

	blockedIDs := make([]string, len(blocks))
	for i, b := range blocks {
		blockedIDs[i] = b.BlockedID
	}

	userMap := make(map[string]*model.User)
	if len(blockedIDs) > 0 {
		var users []model.User
		h.db.Select("id, username, display_name, avatar_url").
			Where("id IN ? AND deleted_at IS NULL", blockedIDs).Find(&users)
		for i := range users {
			userMap[users[i].ID] = &users[i]
		}
	}

	items := make([]gin.H, 0, len(blocks))
	for _, b := range blocks {
		item := gin.H{"user_id": b.BlockedID, "blocked_at": b.CreatedAt}
		if u, ok := userMap[b.BlockedID]; ok {
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

// GET /api/users/:id/block-status (auth)
func (h *FollowHandler) BlockStatus(c *gin.Context) {
	targetUserID := c.Param("id")
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	var count int64
	h.db.Model(&model.UserBlock{}).Where("blocker_id = ? AND blocked_id = ? AND deleted_at IS NULL", uidStr, targetUserID).Count(&count)
	basichttp.OK(c, gin.H{"blocked": count > 0})
}

type batchStatusBody struct {
	UserIDs []string `json:"user_ids" binding:"required"`
}

const maxBatchUserIDs = 500

func normalizeUserIDs(raw []string, max int) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, id := range raw {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
		if len(out) >= max {
			break
		}
	}
	return out
}

// POST /api/users/follow-status/batch (auth)
func (h *FollowHandler) FollowStatusBatch(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	var body batchStatusBody
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}

	ids := normalizeUserIDs(body.UserIDs, maxBatchUserIDs)
	if len(ids) == 0 {
		basichttp.OK(c, gin.H{"items": []gin.H{}})
		return
	}

	var followingIDs []string
	h.db.Model(&model.UserFollow{}).
		Where("follower_id = ? AND following_id IN ? AND deleted_at IS NULL", uidStr, ids).
		Pluck("following_id", &followingIDs)

	followingSet := map[string]struct{}{}
	for _, id := range followingIDs {
		followingSet[id] = struct{}{}
	}

	items := make([]gin.H, 0, len(ids))
	for _, id := range ids {
		_, ok := followingSet[id]
		items = append(items, gin.H{"user_id": id, "following": ok})
	}

	basichttp.OK(c, gin.H{"items": items})
}

// POST /api/users/block-status/batch (auth)
func (h *FollowHandler) BlockStatusBatch(c *gin.Context) {
	uid, _ := c.Get(mw.CtxUserID)
	uidStr := uid.(string)

	var body batchStatusBody
	if err := c.ShouldBindJSON(&body); err != nil {
		basichttp.Fail(c, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "invalid body")
		return
	}

	ids := normalizeUserIDs(body.UserIDs, maxBatchUserIDs)
	if len(ids) == 0 {
		basichttp.OK(c, gin.H{"items": []gin.H{}})
		return
	}

	var blockedIDs []string
	h.db.Model(&model.UserBlock{}).
		Where("blocker_id = ? AND blocked_id IN ? AND deleted_at IS NULL", uidStr, ids).
		Pluck("blocked_id", &blockedIDs)

	blockedSet := map[string]struct{}{}
	for _, id := range blockedIDs {
		blockedSet[id] = struct{}{}
	}

	items := make([]gin.H, 0, len(ids))
	for _, id := range ids {
		_, ok := blockedSet[id]
		items = append(items, gin.H{"user_id": id, "blocked": ok})
	}

	basichttp.OK(c, gin.H{"items": items})
}
