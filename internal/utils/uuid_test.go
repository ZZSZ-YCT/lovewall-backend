package utils

import (
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGenerateUUID(t *testing.T) {
	id1 := GenerateUUID()
	id2 := GenerateUUID()
	
	if id1 == id2 {
		t.Error("Generated UUIDs should be different")
	}
	
	if !IsValidUUID(id1) {
		t.Error("Generated UUID should be valid")
	}
	
	if !IsValidUUID(id2) {
		t.Error("Generated UUID should be valid")
	}
}

func TestIsValidUUID(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{"550E8400-E29B-41D4-A716-446655440000", true},
		{"invalid-uuid", false},
		{"", false},
		{"123", false},
		{"550e8400-e29b-41d4-a716-44665544000g", false},
	}
	
	for _, test := range tests {
		result := IsValidUUID(test.input)
		if result != test.expected {
			t.Errorf("IsValidUUID(%s) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestNormalizeUUID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		{"550E8400-E29B-41D4-A716-446655440000", "550e8400-e29b-41d4-a716-446655440000", false},
		{"  550E8400-E29B-41D4-A716-446655440000  ", "550e8400-e29b-41d4-a716-446655440000", false},
		{"invalid-uuid", "", true},
		{"", "", true},
	}
	
	for _, test := range tests {
		result, err := NormalizeUUID(test.input)
		if test.hasError {
			if err == nil {
				t.Errorf("NormalizeUUID(%s) should return an error", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("NormalizeUUID(%s) should not return an error: %v", test.input, err)
			}
			if result != test.expected {
				t.Errorf("NormalizeUUID(%s) = %s, expected %s", test.input, result, test.expected)
			}
		}
	}
}

func TestGenerateUniqueID(t *testing.T) {
	// Setup in-memory SQLite database for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal("Failed to connect to test database:", err)
	}
	
	// Create a test table
	err = db.Exec("CREATE TABLE test_table (id TEXT PRIMARY KEY)").Error
	if err != nil {
		t.Fatal("Failed to create test table:", err)
	}
	
	// Test generating unique ID
	id1, err := GenerateUniqueID(db, "test_table", "id")
	if err != nil {
		t.Error("GenerateUniqueID should not return an error:", err)
	}
	
	if !IsValidUUID(id1) {
		t.Error("Generated ID should be a valid UUID")
	}
	
	// Insert the ID into the table
	err = db.Exec("INSERT INTO test_table (id) VALUES (?)", id1).Error
	if err != nil {
		t.Fatal("Failed to insert test data:", err)
	}
	
	// Generate another unique ID - should be different
	id2, err := GenerateUniqueID(db, "test_table", "id")
	if err != nil {
		t.Error("GenerateUniqueID should not return an error:", err)
	}
	
	if id1 == id2 {
		t.Error("Generated unique IDs should be different")
	}
}

func TestCheckUUIDExists(t *testing.T) {
	// Setup in-memory SQLite database for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal("Failed to connect to test database:", err)
	}
	
	// Create a test table
	err = db.Exec("CREATE TABLE test_table (id TEXT PRIMARY KEY)").Error
	if err != nil {
		t.Fatal("Failed to create test table:", err)
	}
	
	testID := uuid.NewString()
	
	// Check non-existent ID
	exists, err := CheckUUIDExists(db, "test_table", "id", testID)
	if err != nil {
		t.Error("CheckUUIDExists should not return an error:", err)
	}
	if exists {
		t.Error("ID should not exist initially")
	}
	
	// Insert the ID
	err = db.Exec("INSERT INTO test_table (id) VALUES (?)", testID).Error
	if err != nil {
		t.Fatal("Failed to insert test data:", err)
	}
	
	// Check existing ID
	exists, err = CheckUUIDExists(db, "test_table", "id", testID)
	if err != nil {
		t.Error("CheckUUIDExists should not return an error:", err)
	}
	if !exists {
		t.Error("ID should exist after insertion")
	}
}

func TestValidateAndNormalizeIDs(t *testing.T) {
	input := []string{
		"550E8400-E29B-41D4-A716-446655440000",
		"  550E8400-E29B-41D4-A716-446655440001  ",
		"550e8400-e29b-41d4-a716-446655440002",
	}
	
	expected := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"550e8400-e29b-41d4-a716-446655440001",
		"550e8400-e29b-41d4-a716-446655440002",
	}
	
	result, err := ValidateAndNormalizeIDs(input)
	if err != nil {
		t.Error("ValidateAndNormalizeIDs should not return an error:", err)
	}
	
	if len(result) != len(expected) {
		t.Error("Result length should match expected length")
	}
	
	for i, id := range result {
		if id != expected[i] {
			t.Errorf("Result[%d] = %s, expected %s", i, id, expected[i])
		}
	}
	
	// Test with invalid UUID
	invalidInput := []string{"invalid-uuid"}
	_, err = ValidateAndNormalizeIDs(invalidInput)
	if err == nil {
		t.Error("ValidateAndNormalizeIDs should return an error for invalid UUID")
	}
}

func TestMustGenerateUUID(t *testing.T) {
	id := MustGenerateUUID()
	if !IsValidUUID(id) {
		t.Error("MustGenerateUUID should return a valid UUID")
	}
}