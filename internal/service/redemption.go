package service

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"
)

// RedemptionCodeGenerator generates cryptographically secure redemption codes
type RedemptionCodeGenerator struct{}

// GenerateCode creates a secure, unpredictable redemption code
func (g *RedemptionCodeGenerator) GenerateCode() (string, error) {
	// Generate 20 bytes of random data for high entropy
	randomBytes := make([]byte, 20)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	
	// Use base32 encoding for better readability (no confusing characters)
	encoded := base32.StdEncoding.EncodeToString(randomBytes)
	
	// Remove padding and make it more user-friendly
	code := strings.TrimRight(encoded, "=")
	
	// Format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX (total ~32 chars)
	var formatted strings.Builder
	for i, char := range code {
		if i > 0 && i%4 == 0 {
			formatted.WriteString("-")
		}
		formatted.WriteRune(char)
	}
	
	return formatted.String(), nil
}

// GenerateBatch generates multiple unique codes for a batch
func (g *RedemptionCodeGenerator) GenerateBatch(count int) ([]string, error) {
	if count <= 0 || count > 10000 {
		return nil, fmt.Errorf("invalid batch size: %d (must be 1-10000)", count)
	}
	
	codes := make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	
	for len(codes) < count {
		code, err := g.GenerateCode()
		if err != nil {
			return nil, err
		}
		
		// Ensure uniqueness within batch (extremely unlikely to collide)
		if _, exists := seen[code]; !exists {
			seen[code] = struct{}{}
			codes = append(codes, code)
		}
	}
	
	return codes, nil
}

// GenerateBatchID creates a unique identifier for a batch of codes
func (g *RedemptionCodeGenerator) GenerateBatchID() (string, error) {
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	
	encoded := base32.StdEncoding.EncodeToString(randomBytes)
	encoded = strings.TrimRight(encoded, "=")
	
	return fmt.Sprintf("BATCH_%d_%s", timestamp, encoded), nil
}