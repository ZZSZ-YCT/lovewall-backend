package auth

import (
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

