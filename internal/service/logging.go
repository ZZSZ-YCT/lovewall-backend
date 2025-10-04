package service

import (
	"encoding/json"
	"gorm.io/gorm"
	"lovewall/internal/model"
)

// LogSubmission creates a submission log record.
func LogSubmission(db *gorm.DB, userID, action, objectType, objectID string, metadata map[string]any) {
	var metaStr *string
	if metadata != nil {
		if b, err := json.Marshal(metadata); err == nil {
			s := string(b)
			metaStr = &s
		}
	}
	_ = db.Create(&model.SubmissionLog{
		UserID:     userID,
		Action:     action,
		ObjectType: objectType,
		ObjectID:   objectID,
		Metadata:   metaStr,
	}).Error
}

// LogOperation creates an operation log record for admin actions.
func LogOperation(db *gorm.DB, adminID, action, objectType, objectID string, metadata map[string]any) {
	var metaStr *string
	if metadata != nil {
		if b, err := json.Marshal(metadata); err == nil {
			s := string(b)
			metaStr = &s
		}
	}
	_ = db.Create(&model.OperationLog{
		AdminID:    adminID,
		Action:     action,
		ObjectType: objectType,
		ObjectID:   objectID,
		Metadata:   metaStr,
	}).Error
}

// LogAIModeration creates an AI moderation operation log with fixed AI system UUID.
// Actions: ai_auto_approve, ai_auto_delete, ai_flag_for_review
func LogAIModeration(db *gorm.DB, objectType, objectID, userID string, score int, decision, action, reason string, metadata map[string]any) {
	// Enhance metadata with AI-specific fields
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["user_id"] = userID
	metadata["ai_score"] = score
	metadata["ai_decision"] = decision
	if reason != "" {
		metadata["ai_reason"] = reason
	}

	LogOperation(db, model.AI_SYSTEM_UUID, action, objectType, objectID, metadata)
}
