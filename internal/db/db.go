package db

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"lovewall/internal/config"
	"lovewall/internal/model"
)

func Open(cfg *config.Config) (*gorm.DB, error) {
	if cfg.DBDriver != "sqlite" {
		return nil, errors.New("only sqlite is wired in this skeleton; swap driver in db.Open")
	}
	if cfg.DBDsn == "" {
		return nil, fmt.Errorf("DB_DSN required")
	}

	// Create directory for database file if it doesn't exist
	dbDir := filepath.Dir(cfg.DBDsn)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory %s: %w", dbDir, err)
	}

	// Configure GORM logger to reduce noise and ignore `record not found` situations,
	// which are expected in flows like fetching a user's active tag when none exists yet.
	newLogger := logger.New(
		log.New(os.Stdout, "", log.LstdFlags),
		logger.Config{
			SlowThreshold:             2 * time.Second,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	db, err := gorm.Open(sqlite.Open(cfg.DBDsn), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		return nil, err
	}
	// Tune SQLite to alleviate write contention: WAL + busy_timeout
	_ = db.Exec("PRAGMA journal_mode=WAL;").Error
	_ = db.Exec("PRAGMA busy_timeout=10000;").Error
	_ = db.Exec("PRAGMA synchronous=NORMAL;").Error
	// Optionally tune connection pool
	if sqlDB, err2 := db.DB(); err2 == nil {
		// For SQLite, a small number of conns is recommended
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(0)
	}
	return db, nil
}

func AutoMigrate(db *gorm.DB) error {
	// Drop the garbage request_logs table if it exists
	// This table serves no business purpose and only bloats the database
	if err := dropRequestLogsTable(db); err != nil {
		return fmt.Errorf("drop request_logs table: %w", err)
	}

	// Migrate announcements table from v3.x (title-based) to v4.0 (path-based)
	if err := dropOldAnnouncementsTable(db); err != nil {
		return fmt.Errorf("migrate announcements table to v4.0: %w", err)
	}

	if err := db.AutoMigrate(
		&model.User{},
		&model.ExternalIdentity{},
		&model.Post{},
		&model.PostImage{},
		&model.Comment{},
		&model.Announcement{},
		&model.UserPermission{},
		&model.Tag{},
		&model.RedemptionCode{},
		&model.UserTag{},
		// &model.RequestLog{}, // REMOVED: This is useless garbage that bloats the DB
		&model.SubmissionLog{},
		&model.OperationLog{},
		&model.UserSession{},
		&model.PostView{},
		&model.Notification{},
	); err != nil {
		return err
	}

	if err := db.Exec("UPDATE tags SET tag_type = 'collective' WHERE tag_type IS NULL OR tag_type = ''").Error; err != nil {
		return fmt.Errorf("initialize tag_type values: %w", err)
	}

	// Auto-migrate card_type column
	if err := MigrateCardType(db); err != nil {
		return err
	}

	// Auto-migrate online status columns
	if err := MigrateOnlineStatus(db); err != nil {
		return err
	}

	// Auto-migrate permissions after schema migration
	if err := MigratePermissions(db); err != nil {
		return err
	}

	if err := migratePostCommentFeatures(db); err != nil {
		return fmt.Errorf("migrate post/comment features: %w", err)
	}

	if err := ensurePerformanceIndexes(db); err != nil {
		return fmt.Errorf("ensure performance indexes: %w", err)
	}

	return nil
}

// MigrateCardType adds card_type column to posts table if it doesn't exist
func MigrateCardType(db *gorm.DB) error {
	// Check if card_type column already exists
	var columns []struct {
		Name string
	}
	if err := db.Raw("PRAGMA table_info(posts)").Scan(&columns).Error; err != nil {
		return fmt.Errorf("failed to check posts table schema: %w", err)
	}

	cardTypeExists := false
	for _, col := range columns {
		if col.Name == "card_type" {
			cardTypeExists = true
			break
		}
	}

	if cardTypeExists {
		log.Println("card_type migration already applied, skipping")
		return nil
	}

	log.Println("Applying card_type migration...")

	// Execute migration in transaction
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Add card_type column
	if err := tx.Exec("ALTER TABLE posts ADD COLUMN card_type TEXT NOT NULL DEFAULT 'confession';").Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to add card_type column: %w", err)
	}

	// Create index
	if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_posts_card_type ON posts(card_type);").Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to create card_type index: %w", err)
	}

	// Backfill existing data
	if err := tx.Exec("UPDATE posts SET card_type = 'confession' WHERE card_type IS NULL OR card_type = '';").Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to backfill card_type: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit card_type migration: %w", err)
	}

	log.Println("card_type migration completed successfully")
	return nil
}

// MigrateOnlineStatus adds is_online and last_heartbeat columns to users table if they don't exist
func MigrateOnlineStatus(db *gorm.DB) error {
	var columns []struct {
		Name string
	}
	if err := db.Raw("PRAGMA table_info(users)").Scan(&columns).Error; err != nil {
		return fmt.Errorf("failed to check users table schema: %w", err)
	}

	isOnlineExists := false
	lastHeartbeatExists := false
	for _, col := range columns {
		if col.Name == "is_online" {
			isOnlineExists = true
		}
		if col.Name == "last_heartbeat" {
			lastHeartbeatExists = true
		}
	}

	if isOnlineExists && lastHeartbeatExists {
		log.Println("online status migration already applied, skipping")
		return nil
	}

	log.Println("Applying online status migration...")

	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if !isOnlineExists {
		if err := tx.Exec("ALTER TABLE users ADD COLUMN is_online INTEGER NOT NULL DEFAULT 0;").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to add is_online column: %w", err)
		}
		if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_users_is_online ON users(is_online);").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to create is_online index: %w", err)
		}
	}

	if !lastHeartbeatExists {
		if err := tx.Exec("ALTER TABLE users ADD COLUMN last_heartbeat DATETIME;").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to add last_heartbeat column: %w", err)
		}
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit online status migration: %w", err)
	}

	log.Println("online status migration completed successfully")
	return nil
}

// MigratePermissions migrates old permissions to new granular permission system
func MigratePermissions(db *gorm.DB) error {
	// Check if old permissions exist
	var oldPermCount int64
	db.Model(&model.UserPermission{}).
		Where("permission IN (?, ?, ?, ?, ?) AND deleted_at IS NULL",
			"HIDE_POST", "DELETE_POST", "EDIT_POST", "PIN_POST", "FEATURE_POST").
		Count(&oldPermCount)

	if oldPermCount == 0 {
		// No old permissions to migrate
		return nil
	}

	log.Println("Migrating old permissions to new granular system...")

	// Start transaction
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 1. Migrate HIDE_POST, DELETE_POST, EDIT_POST -> MANAGE_POSTS
	var postAdminUsers []string
	tx.Model(&model.UserPermission{}).
		Where("permission IN (?, ?, ?) AND deleted_at IS NULL", "HIDE_POST", "DELETE_POST", "EDIT_POST").
		Distinct("user_id").
		Pluck("user_id", &postAdminUsers)

	for _, userID := range postAdminUsers {
		// Check if MANAGE_POSTS already exists
		var count int64
		tx.Model(&model.UserPermission{}).
			Where("user_id = ? AND permission = ? AND deleted_at IS NULL", userID, "MANAGE_POSTS").
			Count(&count)

		if count == 0 {
			perm := &model.UserPermission{
				UserID:     userID,
				Permission: "MANAGE_POSTS",
			}
			if err := tx.Create(perm).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to create MANAGE_POSTS for user %s: %w", userID, err)
			}
		}
	}

	// 2. Migrate PIN_POST, FEATURE_POST -> MANAGE_FEATURED
	var featuredAdminUsers []string
	tx.Model(&model.UserPermission{}).
		Where("permission IN (?, ?) AND deleted_at IS NULL", "PIN_POST", "FEATURE_POST").
		Distinct("user_id").
		Pluck("user_id", &featuredAdminUsers)

	for _, userID := range featuredAdminUsers {
		var count int64
		tx.Model(&model.UserPermission{}).
			Where("user_id = ? AND permission = ? AND deleted_at IS NULL", userID, "MANAGE_FEATURED").
			Count(&count)

		if count == 0 {
			perm := &model.UserPermission{
				UserID:     userID,
				Permission: "MANAGE_FEATURED",
			}
			if err := tx.Create(perm).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to create MANAGE_FEATURED for user %s: %w", userID, err)
			}
		}
	}

	// 3. Soft-delete old permissions
	now := time.Now()
	if err := tx.Model(&model.UserPermission{}).
		Where("permission IN (?, ?, ?, ?, ?) AND deleted_at IS NULL",
			"HIDE_POST", "DELETE_POST", "EDIT_POST", "PIN_POST", "FEATURE_POST").
		Update("deleted_at", now).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to soft-delete old permissions: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit permission migration: %w", err)
	}

	log.Printf("Permission migration completed: %d old permissions migrated\n", oldPermCount)
	return nil
}

func ensurePerformanceIndexes(db *gorm.DB) error {
	statements := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_username_active ON users(username) WHERE deleted_at IS NULL",
		"CREATE INDEX IF NOT EXISTS idx_users_display_name_active ON users(display_name) WHERE display_name IS NOT NULL AND deleted_at IS NULL",
		"CREATE INDEX IF NOT EXISTS idx_users_is_banned ON users(is_banned, deleted_at)",
		"CREATE INDEX IF NOT EXISTS idx_tags_title_active ON tags(title) WHERE deleted_at IS NULL",
		"CREATE INDEX IF NOT EXISTS idx_tags_is_active ON tags(is_active, deleted_at)",
	}

	for _, stmt := range statements {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("create index %s: %w", stmt, err)
		}
	}
	return nil
}

// migratePostCommentFeatures adds is_locked to posts and is_pinned to comments,
// and merges MANAGE_COMMENTS permission into MANAGE_POSTS
func migratePostCommentFeatures(db *gorm.DB) error {
	// 1. Add is_locked column to posts if not exists
	if !db.Migrator().HasColumn(&model.Post{}, "is_locked") {
		if err := db.Migrator().AddColumn(&model.Post{}, "is_locked"); err != nil {
			return fmt.Errorf("add is_locked column: %w", err)
		}
	}

	// 2. Add is_pinned column to comments if not exists
	if !db.Migrator().HasColumn(&model.Comment{}, "is_pinned") {
		if err := db.Migrator().AddColumn(&model.Comment{}, "is_pinned"); err != nil {
			return fmt.Errorf("add is_pinned column: %w", err)
		}
	}

	// 3. Merge MANAGE_COMMENTS into MANAGE_POSTS
	// First, delete existing MANAGE_POSTS for users who also have MANAGE_COMMENTS
	// This prevents UNIQUE constraint violation
	if err := db.Exec(`
		DELETE FROM user_permissions
		WHERE permission = 'MANAGE_POSTS'
		AND deleted_at IS NULL
		AND user_id IN (
			SELECT user_id
			FROM user_permissions
			WHERE permission = 'MANAGE_COMMENTS'
			AND deleted_at IS NULL
		)
	`).Error; err != nil {
		return fmt.Errorf("delete existing MANAGE_POSTS: %w", err)
	}

	// Then update all MANAGE_COMMENTS to MANAGE_POSTS
	if err := db.Exec(`
		UPDATE user_permissions
		SET permission = 'MANAGE_POSTS'
		WHERE permission = 'MANAGE_COMMENTS'
		AND deleted_at IS NULL
	`).Error; err != nil {
		return fmt.Errorf("merge MANAGE_COMMENTS: %w", err)
	}

	// 4. Clean up empty string values in nullable fields
	// Convert empty strings to NULL for proper nullable field handling
	if err := db.Exec(`
		UPDATE users
		SET display_name = NULL
		WHERE display_name = ''
		AND deleted_at IS NULL
	`).Error; err != nil {
		return fmt.Errorf("clean display_name: %w", err)
	}

	if err := db.Exec(`
		UPDATE users
		SET email = NULL
		WHERE email = ''
		AND deleted_at IS NULL
	`).Error; err != nil {
		return fmt.Errorf("clean email: %w", err)
	}

	if err := db.Exec(`
		UPDATE users
		SET phone = NULL
		WHERE phone = ''
		AND deleted_at IS NULL
	`).Error; err != nil {
		return fmt.Errorf("clean phone: %w", err)
	}

	if err := db.Exec(`
		UPDATE users
		SET bio = NULL
		WHERE bio = ''
		AND deleted_at IS NULL
	`).Error; err != nil {
		return fmt.Errorf("clean bio: %w", err)
	}

	if err := db.Exec(`
		UPDATE users
		SET avatar_url = NULL
		WHERE avatar_url = ''
		AND deleted_at IS NULL
	`).Error; err != nil {
		return fmt.Errorf("clean avatar_url: %w", err)
	}

	return nil
}

// dropRequestLogsTable drops the request_logs table if it exists.
// This table is useless garbage that stores every HTTP request and bloats the database.
// Business value: ZERO. The only logs we need are submission logs and operation logs.
func dropRequestLogsTable(db *gorm.DB) error {
	// Check if request_logs table exists
	var tableExists int
	if err := db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='request_logs'").Scan(&tableExists).Error; err != nil {
		return fmt.Errorf("check request_logs table existence: %w", err)
	}

	if tableExists > 0 {
		log.Println("Detected garbage request_logs table, dropping it to reclaim space...")

		// Drop the table
		if err := db.Exec("DROP TABLE request_logs").Error; err != nil {
			return fmt.Errorf("drop request_logs table: %w", err)
		}
		log.Println("request_logs table dropped successfully.")

		// CRITICAL: VACUUM to actually reclaim disk space
		// Without VACUUM, SQLite just marks the pages as reusable but doesn't shrink the file
		log.Println("Running VACUUM to reclaim disk space (this may take a while)...")
		// Best-effort: don't block startup if VACUUM fails (e.g., database is locked)
		if err := db.Exec("VACUUM").Error; err != nil {
			log.Printf("WARNING: VACUUM failed (database may still be bloated): %v", err)
		} else {
			log.Println("VACUUM completed successfully.")

			// In WAL mode, also checkpoint and truncate the WAL file
			log.Println("Checkpointing WAL to reclaim WAL file space...")
			if err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error; err != nil {
				log.Printf("WARNING: WAL checkpoint failed: %v", err)
			} else {
				log.Println("WAL checkpoint completed. Database file size should be much smaller now.")
			}
		}
	}

	return nil
}

// dropOldAnnouncementsTable removes the old title-based announcements table
// and prepares for the new path-based schema (v4.0)
func dropOldAnnouncementsTable(db *gorm.DB) error {
	// Check if announcements table exists with old schema (has 'title' column)
	var columns []struct {
		Name string
	}

	// First check if table exists
	var tableExists int
	if err := db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='announcements'").Scan(&tableExists).Error; err != nil {
		return fmt.Errorf("check announcements table existence: %w", err)
	}

	if tableExists == 0 {
		// Table doesn't exist, nothing to do
		return nil
	}

	// Check if it has the old 'title' column
	if err := db.Raw("PRAGMA table_info(announcements)").Scan(&columns).Error; err != nil {
		return fmt.Errorf("failed to check announcements table schema: %w", err)
	}

	hasTitleColumn := false
	hasPathColumn := false
	for _, col := range columns {
		if col.Name == "title" {
			hasTitleColumn = true
		}
		if col.Name == "path" {
			hasPathColumn = true
		}
	}

	// If it has 'path' but not 'title', it's already the new schema
	if hasPathColumn && !hasTitleColumn {
		log.Println("Announcements table already migrated to v4.0 (path-based), skipping drop.")
		return nil
	}

	// If it has 'title' column, it's the old schema - drop it
	if hasTitleColumn {
		log.Println("Detected old title-based announcements table (v3.x), migrating to v4.0...")
		log.Println("Dropping old announcements table (data will be lost, but table was rarely used)...")

		// Drop the old table
		if err := db.Exec("DROP TABLE announcements").Error; err != nil {
			return fmt.Errorf("drop old announcements table: %w", err)
		}
		log.Println("Old announcements table dropped successfully.")

		// VACUUM to reclaim space (best-effort)
		log.Println("Running VACUUM to reclaim disk space...")
		if err := db.Exec("VACUUM").Error; err != nil {
			log.Printf("WARNING: VACUUM failed: %v", err)
		} else {
			log.Println("VACUUM completed successfully.")
		}
	}

	return nil
}
