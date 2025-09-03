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
    return db, nil
}

func AutoMigrate(db *gorm.DB) error {
    return db.AutoMigrate(
        &model.User{},
        &model.ExternalIdentity{},
        &model.Post{},
        &model.Comment{},
        &model.Announcement{},
        &model.UserPermission{},
        &model.Tag{},
        &model.RedemptionCode{},
        &model.UserTag{},
    )
}
