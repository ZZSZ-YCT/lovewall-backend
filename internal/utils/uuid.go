package utils

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ErrDuplicateID is returned when a generated UUID already exists
var ErrDuplicateID = errors.New("duplicate ID generated")

// GenerateUUID generates a new UUID string
func GenerateUUID() string {
	return uuid.NewString()
}

// IsValidUUID checks if the given string is a valid UUID
func IsValidUUID(uuidStr string) bool {
	_, err := uuid.Parse(uuidStr)
	return err == nil
}

// NormalizeUUID normalizes the UUID string to lowercase and validates it
func NormalizeUUID(uuidStr string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(uuidStr))
	if !IsValidUUID(normalized) {
		return "", errors.New("invalid UUID format")
	}
	return normalized, nil
}

// GenerateUniqueID generates a unique ID for the specified table and column
// It checks against the database to ensure uniqueness
func GenerateUniqueID(db *gorm.DB, tableName, columnName string) (string, error) {
	const maxAttempts = 10
	
	for i := 0; i < maxAttempts; i++ {
		id := GenerateUUID()
		
		// Check if ID already exists in the table
		var count int64
		if err := db.Table(tableName).Where(columnName+" = ?", id).Count(&count).Error; err != nil {
			return "", err
		}
		
		if count == 0 {
			return id, nil
		}
	}
	
	return "", ErrDuplicateID
}

// CheckUUIDExists checks if a UUID exists in the specified table and column
func CheckUUIDExists(db *gorm.DB, tableName, columnName, id string) (bool, error) {
	var count int64
	err := db.Table(tableName).Where(columnName+" = ?", id).Count(&count).Error
	return count > 0, err
}

// ValidateAndNormalizeIDs validates and normalizes a slice of UUID strings
func ValidateAndNormalizeIDs(ids []string) ([]string, error) {
	normalized := make([]string, len(ids))
	for i, id := range ids {
		norm, err := NormalizeUUID(id)
		if err != nil {
			return nil, err
		}
		normalized[i] = norm
	}
	return normalized, nil
}

// MustGenerateUUID generates a UUID and panics if it fails
// Use with caution - only in situations where UUID generation failure is unrecoverable
func MustGenerateUUID() string {
	id := GenerateUUID()
	if id == "" {
		panic("failed to generate UUID")
	}
	return id
}