package service

import (
	"regexp"

	"gorm.io/gorm"

	"lovewall/internal/model"
)

var mentionRe = regexp.MustCompile(`@([a-zA-Z0-9_]{3,32})`)

// ParseMentions extracts unique @usernames from content.
func ParseMentions(content string) []string {
	matches := mentionRe.FindAllStringSubmatch(content, -1)
	seen := make(map[string]struct{}, len(matches))
	result := make([]string, 0, len(matches))
	for _, m := range matches {
		username := m[1]
		if _, ok := seen[username]; ok {
			continue
		}
		seen[username] = struct{}{}
		result = append(result, username)
	}
	return result
}

// ResolveMentions validates usernames against the database and returns valid users.
func ResolveMentions(db *gorm.DB, usernames []string) []model.User {
	if len(usernames) == 0 {
		return nil
	}
	var users []model.User
	db.Select("id, username, display_name").
		Where("username IN ? AND deleted_at IS NULL", usernames).
		Find(&users)
	return users
}

// CreateMentions parses @mentions from content, creates PostMention records,
// and sends notifications to mentioned users. Returns the created mentions.
func CreateMentions(db *gorm.DB, postID, authorID string, content string) []model.PostMention {
	usernames := ParseMentions(content)
	if len(usernames) == 0 {
		return nil
	}
	users := ResolveMentions(db, usernames)
	if len(users) == 0 {
		return nil
	}

	mentions := make([]model.PostMention, 0, len(users))
	for _, u := range users {
		if u.ID == authorID {
			continue // don't mention yourself
		}
		mention := model.PostMention{
			PostID:          postID,
			MentionedUserID: u.ID,
			Username:        u.Username,
		}
		if err := db.Create(&mention).Error; err != nil {
			continue
		}
		mentions = append(mentions, mention)
		// Notify mentioned user
		Notify(db, u.ID, "有人提到了你", "你被 @提及 了，点击查看详情。", map[string]any{
			"post_id":   postID,
			"author_id": authorID,
			"type":      "mention",
		})
	}
	return mentions
}
