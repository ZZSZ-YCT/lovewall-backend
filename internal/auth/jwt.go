package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Sub          string `json:"sub"`
	IsSuperadmin bool   `json:"is_superadmin"`
	jwt.RegisteredClaims
}

func Sign(secret, sub string, isSuper bool, ttlSeconds int64) (string, error) {
	now := time.Now()
	claims := Claims{
		Sub:          sub,
		IsSuperadmin: isSuper,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttlSeconds) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   sub,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// genJTI produces a cryptographically random 128-bit identifier encoded as hex.
func genJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SignWithJTI signs a JWT like Sign, but also sets a unique JWT ID (jti)
// and returns it alongside the token string for session tracking.
func SignWithJTI(secret, sub string, isSuper bool, ttlSeconds int64) (tokenStr string, jti string, err error) {
	now := time.Now()
	jti, err = genJTI()
	if err != nil {
		return "", "", err
	}
	claims := Claims{
		Sub:          sub,
		IsSuperadmin: isSuper,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttlSeconds) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   sub,
			ID:        jti,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err = token.SignedString([]byte(secret))
	return
}

func Parse(secret, tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrInvalidKey
}
