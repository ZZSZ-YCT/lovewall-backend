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