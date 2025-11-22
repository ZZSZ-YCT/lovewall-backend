package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"

	"lovewall/internal/model"
)

const (
	MFATypeTOTP      = "totp"
	MFATypeRecovery  = "recovery_code"
	defaultIssuer    = "LoveWall"
	defaultCodeCount = 10
)

// GenerateTOTPSecret creates a new TOTP secret and provisioning URI.
// Issuer fallback is defaultIssuer when empty.
func GenerateTOTPSecret(username, issuer string) (secret string, uri string, err error) {
	issuerVal := strings.TrimSpace(issuer)
	if issuerVal == "" {
		issuerVal = defaultIssuer
	}
	account := strings.TrimSpace(username)
	if account == "" {
		account = "user"
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuerVal,
		AccountName: account,
		Period:      30,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTOTP checks whether the code is valid for the secret.
func ValidateTOTP(secret, code string) bool {
	clean := normalizeCode(code)
	if clean == "" {
		return false
	}
	return totp.Validate(clean, secret)
}

// HasVerifiedMFA returns true if the user has at least one verified MFA factor.
func HasVerifiedMFA(db *gorm.DB, userID string) bool {
	var cnt int64
	db.Model(&model.UserMFA{}).
		Where("user_id = ? AND is_verified = ? AND deleted_at IS NULL", userID, true).
		Count(&cnt)
	if cnt > 0 {
		return true
	}
	db.Model(&model.PasskeyCredential{}).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		Count(&cnt)
	return cnt > 0
}

// VerifyMFA validates a TOTP or recovery code. Returns the method used on success.
func VerifyMFA(db *gorm.DB, userID, totpCode, recoveryCode string) (string, error) {
	totpCode = normalizeCode(totpCode)
	recoveryCode = normalizeCode(recoveryCode)

	if totpCode != "" {
		var factor model.UserMFA
		err := db.Where("user_id = ? AND type = ? AND is_verified = ? AND deleted_at IS NULL", userID, MFATypeTOTP, true).
			Order("created_at DESC").
			First(&factor).Error
		if err == nil && ValidateTOTP(factor.Secret, totpCode) {
			now := time.Now()
			_ = db.Model(&factor).Update("last_used_at", now).Error
			return MFATypeTOTP, nil
		}
	}

	if recoveryCode != "" {
		hash := hashRecoveryCode(recoveryCode)
		var rec model.MFARecoveryCode
		err := db.Where("user_id = ? AND code_hash = ? AND used = ? AND deleted_at IS NULL", userID, hash, false).
			Order("created_at DESC").
			First(&rec).Error
		if err == nil {
			now := time.Now()
			_ = db.Model(&rec).Updates(map[string]any{"used": true, "used_at": now}).Error
			return MFATypeRecovery, nil
		}
	}

	return "", errors.New("invalid mfa code")
}

// GenerateRecoveryCodes builds a list of human-friendly recovery codes.
func GenerateRecoveryCodes(count int) ([]string, error) {
	if count <= 0 {
		count = defaultCodeCount
	}
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

// ReplaceRecoveryCodes overwrites all recovery codes for a user.
func ReplaceRecoveryCodes(db *gorm.DB, userID string, codes []string) error {
	if len(codes) == 0 {
		return errors.New("no recovery codes provided")
	}
	tx := db.Begin()
	if err := tx.Error; err != nil {
		return err
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.MFARecoveryCode{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	for _, code := range codes {
		rc := model.MFARecoveryCode{
			UserID:   userID,
			CodeHash: hashRecoveryCode(code),
			Used:     false,
		}
		if err := tx.Create(&rc).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

// RecoveryCodesRemaining returns the number of unused recovery codes.
func RecoveryCodesRemaining(db *gorm.DB, userID string) int {
	var cnt int64
	db.Model(&model.MFARecoveryCode{}).
		Where("user_id = ? AND used = ? AND deleted_at IS NULL", userID, false).
		Count(&cnt)
	return int(cnt)
}

// ListMFAFactors fetches factors for the user without secrets.
func ListMFAFactors(db *gorm.DB, userID string) ([]model.UserMFA, error) {
	var factors []model.UserMFA
	if err := db.Select("id", "user_id", "type", "is_verified", "label", "last_used_at", "created_at", "updated_at").
		Where("user_id = ? AND deleted_at IS NULL", userID).
		Order("created_at DESC").
		Find(&factors).Error; err != nil {
		return nil, err
	}
	return factors, nil
}

func generateRecoveryCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	hexed := strings.ToUpper(hex.EncodeToString(buf))
	// Format like XXXX-XXXX-XXXX-XXXX for readability
	if len(hexed) < 16 {
		return "", fmt.Errorf("generated code too short")
	}
	return hexed[0:4] + "-" + hexed[4:8] + "-" + hexed[8:12] + "-" + hexed[12:16], nil
}

func normalizeCode(code string) string {
	c := strings.TrimSpace(code)
	c = strings.ReplaceAll(c, " ", "")
	c = strings.ReplaceAll(c, "-", "")
	return c
}

func hashRecoveryCode(code string) string {
	clean := strings.ToLower(normalizeCode(code))
	sum := sha256.Sum256([]byte(clean))
	return hex.EncodeToString(sum[:])
}
