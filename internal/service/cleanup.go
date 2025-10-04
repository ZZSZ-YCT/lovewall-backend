package service

import (
	"gorm.io/gorm"
)

// CleanupOrphanedTagRelations removes dangling user_tags and redemption_codes
// that reference deleted/non-existent tags. Invoke on application startup.
func CleanupOrphanedTagRelations(db *gorm.DB) {
	// Delete user_tags whose tag_id no longer exists (or tag soft-deleted)
	db.Exec("DELETE FROM user_tags WHERE tag_id NOT IN (SELECT id FROM tags WHERE deleted_at IS NULL)")
	// Delete redemption_codes whose tag_id no longer exists (or tag soft-deleted)
	db.Exec("DELETE FROM redemption_codes WHERE tag_id NOT IN (SELECT id FROM tags WHERE deleted_at IS NULL)")
}
