package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"

	"lovewall/internal/config"
	"lovewall/internal/model"
)

var (
	ErrWebAuthnNotConfigured = errors.New("passkey not configured")
)

type WebAuthnService struct {
	db    *gorm.DB
	cache Cache
	wa    *webauthn.WebAuthn
}

// NewWebAuthnService returns a configured service or nil when rp settings are missing.
func NewWebAuthnService(cfg *config.Config, db *gorm.DB, cache Cache) (*WebAuthnService, error) {
	if cfg.WebAuthnRPID == "" || cfg.WebAuthnOrigin == "" {
		return nil, ErrWebAuthnNotConfigured
	}
	name := cfg.WebAuthnRPName
	if strings.TrimSpace(name) == "" {
		name = "LoveWall"
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName:         name,
		RPID:                  cfg.WebAuthnRPID,
		RPOrigin:              cfg.WebAuthnOrigin,
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, err
	}
	return &WebAuthnService{db: db, cache: cache, wa: wa}, nil
}

// --- Registration (logged-in) ---

func (s *WebAuthnService) BeginRegistration(ctx context.Context, user *model.User) (*protocol.CredentialCreation, string, error) {
	if s == nil || s.wa == nil {
		return nil, "", ErrWebAuthnNotConfigured
	}
	wUser, err := s.buildUser(user)
	if err != nil {
		return nil, "", err
	}
	opts := func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.AuthenticatorSelection = protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}
		cco.Attestation = protocol.PreferNoAttestation
	}
	credentialOpts, sessionData, err := s.wa.BeginRegistration(wUser, opts)
	if err != nil {
		return nil, "", err
	}
	state, err := randomState()
	if err != nil {
		return nil, "", err
	}
	if err := s.cacheSession(ctx, "register", state, sessionData); err != nil {
		return nil, "", err
	}
	return credentialOpts, state, nil
}

func (s *WebAuthnService) FinishRegistration(ctx context.Context, user *model.User, state string, req *http.Request) error {
	if s == nil || s.wa == nil {
		return ErrWebAuthnNotConfigured
	}
	sessionData, err := s.loadSession(ctx, "register", state)
	if err != nil {
		return err
	}
	wUser, err := s.buildUser(user)
	if err != nil {
		return err
	}
	cred, err := s.wa.FinishRegistration(wUser, *sessionData, req)
	if err != nil {
		return err
	}
	return s.persistCredential(user.ID, cred)
}

// --- Assertion (login/passkey MFA) ---

func (s *WebAuthnService) BeginLogin(ctx context.Context, user *model.User) (*protocol.CredentialAssertion, string, error) {
	if s == nil || s.wa == nil {
		return nil, "", ErrWebAuthnNotConfigured
	}
	wUser, err := s.buildUser(user)
	if err != nil {
		return nil, "", err
	}
	opts := func(lao *protocol.PublicKeyCredentialRequestOptions) {
		lao.UserVerification = protocol.VerificationPreferred
	}
	assertion, sessionData, err := s.wa.BeginLogin(wUser, opts)
	if err != nil {
		return nil, "", err
	}
	state, err := randomState()
	if err != nil {
		return nil, "", err
	}
	if err := s.cacheSession(ctx, "login", state, sessionData); err != nil {
		return nil, "", err
	}
	return assertion, state, nil
}

func (s *WebAuthnService) FinishLogin(ctx context.Context, user *model.User, state string, req *http.Request) error {
	if s == nil || s.wa == nil {
		return ErrWebAuthnNotConfigured
	}
	sessionData, err := s.loadSession(ctx, "login", state)
	if err != nil {
		return err
	}
	wUser, err := s.buildUser(user)
	if err != nil {
		return err
	}
	cred, err := s.wa.FinishLogin(wUser, *sessionData, req)
	if err != nil {
		return err
	}
	// Update sign counter and last used
	now := time.Now()
	credID := base64.RawStdEncoding.EncodeToString(cred.ID)
	_ = s.db.Model(&model.PasskeyCredential{}).
		Where("credential_id = ? AND user_id = ?", credID, user.ID).
		Updates(map[string]any{"sign_count": cred.Authenticator.SignCount, "last_used_at": now}).Error
	return nil
}

// --- Helpers ---

func (s *WebAuthnService) buildUser(user *model.User) (*waUser, error) {
	var creds []model.PasskeyCredential
	if err := s.db.Where("user_id = ? AND deleted_at IS NULL", user.ID).Find(&creds).Error; err != nil {
		return nil, err
	}
	return &waUser{user: *user, creds: creds}, nil
}

func (s *WebAuthnService) persistCredential(userID string, cred *webauthn.Credential) error {
	credID := base64.RawStdEncoding.EncodeToString(cred.ID)
	pubKey := base64.RawStdEncoding.EncodeToString(cred.PublicKey)
	transports := ""
	if len(cred.Transport) > 0 {
		t := make([]string, 0, len(cred.Transport))
		for _, tr := range cred.Transport {
			t = append(t, string(tr))
		}
		transports = strings.Join(t, ",")
	}
	record := model.PasskeyCredential{
		UserID:          userID,
		CredentialID:    credID,
		PublicKey:       pubKey,
		SignCount:       cred.Authenticator.SignCount,
		AttestationType: cred.AttestationType,
		AAGUID:          hex.EncodeToString(cred.Authenticator.AAGUID),
		Transports:      strPtrOrNil(transports),
		Discoverable:    false,
	}
	// Upsert on cred id to avoid duplicates
	var existing model.PasskeyCredential
	err := s.db.First(&existing, "credential_id = ?", credID).Error
	if err == nil {
		_ = s.db.Model(&existing).Updates(map[string]any{
			"user_id":          userID,
			"public_key":       record.PublicKey,
			"sign_count":       record.SignCount,
			"attestation_type": record.AttestationType,
			"aaguid":           record.AAGUID,
			"transports":       record.Transports,
			"discoverable":     record.Discoverable,
		}).Error
	} else {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err := s.db.Create(&record).Error; err != nil {
			return err
		}
	}
	// Mark MFA presence
	marker := model.UserMFA{
		UserID:     userID,
		Type:       "passkey",
		IsVerified: true,
		Label:      strPtrOrNil("passkey"),
	}
	// Upsert marker
	var m model.UserMFA
	if err := s.db.First(&m, "user_id = ? AND type = ?", userID, "passkey").Error; err == nil {
		_ = s.db.Model(&m).Updates(map[string]any{"is_verified": true, "label": marker.Label})
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		_ = s.db.Create(&marker).Error
	}
	return nil
}

func (s *WebAuthnService) cacheSession(ctx context.Context, purpose, state string, sd *webauthn.SessionData) error {
	if s.cache == nil {
		return errors.New("cache not initialized")
	}
	raw, err := json.Marshal(sd)
	if err != nil {
		return err
	}
	key := sessionCacheKey(purpose, state)
	return s.cache.Set(ctx, key, raw, 10*time.Minute)
}

func (s *WebAuthnService) loadSession(ctx context.Context, purpose, state string) (*webauthn.SessionData, error) {
	if s.cache == nil {
		return nil, errors.New("cache not initialized")
	}
	key := sessionCacheKey(purpose, state)
	raw, ok, err := s.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("session expired or invalid")
	}
	data := &webauthn.SessionData{}
	if err := json.Unmarshal(raw, data); err != nil {
		return nil, err
	}
	_ = s.cache.Delete(ctx, key) // best-effort one-time use
	return data, nil
}

func sessionCacheKey(purpose, state string) string {
	return fmt.Sprintf("webauthn:%s:%s", purpose, state)
}

func randomState() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func strPtrOrNil(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

// waUser implements webauthn.User
type waUser struct {
	user  model.User
	creds []model.PasskeyCredential
}

func (u *waUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u *waUser) WebAuthnName() string {
	return u.user.Username
}

func (u *waUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != nil && strings.TrimSpace(*u.user.DisplayName) != "" {
		return *u.user.DisplayName
	}
	return u.user.Username
}

func (u *waUser) WebAuthnIcon() string { return "" }

func (u *waUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.creds))
	for _, c := range u.creds {
		id, err := base64.RawStdEncoding.DecodeString(c.CredentialID)
		if err != nil {
			continue
		}
		pk, err := base64.RawStdEncoding.DecodeString(c.PublicKey)
		if err != nil {
			continue
		}
		var aaguidBytes []byte
		if c.AAGUID != "" {
			if decoded, err := hex.DecodeString(c.AAGUID); err == nil {
				aaguidBytes = decoded
			}
		}
		transports := []string{}
		if c.Transports != nil && *c.Transports != "" {
			transports = strings.Split(*c.Transports, ",")
		}
		authTransports := make([]protocol.AuthenticatorTransport, 0, len(transports))
		for _, t := range transports {
			if strings.TrimSpace(t) == "" {
				continue
			}
			authTransports = append(authTransports, protocol.AuthenticatorTransport(t))
		}
		out = append(out, webauthn.Credential{
			ID:              id,
			PublicKey:       pk,
			AttestationType: c.AttestationType,
			Transport:       authTransports,
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguidBytes,
				SignCount: c.SignCount,
			},
		})
	}
	return out
}

// HasPasskey reports whether the user has at least one WebAuthn credential.
func HasPasskey(db *gorm.DB, userID string) bool {
	var cnt int64
	db.Model(&model.PasskeyCredential{}).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		Count(&cnt)
	return cnt > 0
}
