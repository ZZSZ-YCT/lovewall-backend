package service

import (
	"encoding/json"
	"gorm.io/gorm"
	"lovewall/internal/model"
)

func Notify(db *gorm.DB, userID, title, content string, meta map[string]any) {
	var metaStr *string
	if meta != nil {
		if b, err := json.Marshal(meta); err == nil {
			s := string(b)
			metaStr = &s
		}
	}
	_ = db.Create(&model.Notification{UserID: userID, Title: title, Content: content, Metadata: metaStr}).Error
}
