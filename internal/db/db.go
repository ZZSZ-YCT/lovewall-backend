package db

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"

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
    
    db, err := gorm.Open(sqlite.Open(cfg.DBDsn), &gorm.Config{
        Logger: logger.Default.LogMode(logger.Warn),
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

