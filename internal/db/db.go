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
		&model.RequestLog{},
		&model.SubmissionLog{},
		&model.OperationLog{},
		&model.UserSession{},
		&model.PostView{},
		&model.Notification{},
	); err != nil {
		return err
	}

	// Auto-migrate permissions after schema migration
	return MigratePermissions(db)
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
