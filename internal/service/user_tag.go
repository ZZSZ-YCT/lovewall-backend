package service

import (
	"gorm.io/gorm"
	"lovewall/internal/model"
)

type UserTagService struct {
	db *gorm.DB
}

func NewUserTagService(db *gorm.DB) *UserTagService {
	return &UserTagService{db: db}
}

// GetActiveUserTag returns the currently active tag for a user
func (s *UserTagService) GetActiveUserTag(userID string) (*model.Tag, error) {
	var userTag model.UserTag
	err := s.db.Preload("Tag").First(&userTag,
		"user_id = ? AND is_active = ? AND deleted_at IS NULL",
		userID, true).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // No active tag
		}
		return nil, err
	}

	// Check if tag is still active
	if !userTag.Tag.IsActive {
		return nil, nil
	}

	return &userTag.Tag, nil
}

// GetActiveUserTagsBatch returns active tags for multiple users in one query.
// It returns a map of userID -> tag pointer.
func (s *UserTagService) GetActiveUserTagsBatch(userIDs []string) (map[string]*model.Tag, error) {
	if len(userIDs) == 0 {
		return make(map[string]*model.Tag), nil
	}

	var userTags []model.UserTag
	err := s.db.Preload("Tag").
		Joins("JOIN tags ON tags.id = user_tags.tag_id").
		Where("user_tags.user_id IN ? AND user_tags.is_active = ? AND user_tags.deleted_at IS NULL", userIDs, true).
		Where("tags.deleted_at IS NULL AND tags.is_active = ?", true).
		Find(&userTags).Error
	if err != nil {
		return nil, err
	}

	result := make(map[string]*model.Tag, len(userTags))
	for i := range userTags {
		result[userTags[i].UserID] = &userTags[i].Tag
	}
	return result, nil
}

// GetUserTags returns all tags for a user
func (s *UserTagService) GetUserTags(userID string) ([]model.UserTag, error) {
	var userTags []model.UserTag
	err := s.db.Preload("Tag").Where(
		"user_id = ? AND deleted_at IS NULL",
		userID).Find(&userTags).Error

	if err != nil {
		return nil, err
	}

	return userTags, nil
}

// HasTag checks if a user has a specific tag
func (s *UserTagService) HasTag(userID, tagID string) bool {
	var count int64
	s.db.Model(&model.UserTag{}).Where(
		"user_id = ? AND tag_id = ? AND deleted_at IS NULL",
		userID, tagID).Count(&count)

	return count > 0
}
