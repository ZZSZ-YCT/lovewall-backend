package middleware

import (
    "net/http"
    "strings"
    "time"

    basichttp "lovewall/internal/http"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
    "go.uber.org/zap"
    "gorm.io/gorm"
)

func RequestLogger() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        c.Next()
        zap.L().Info("http",
            zap.String("method", c.Request.Method),
            zap.String("path", c.Request.URL.Path),
            zap.Int("status", c.Writer.Status()),
            zap.Duration("dur", time.Since(start)),
            zap.String("ip", c.ClientIP()),
        )
    }
}

type UserClaims struct {
    Sub           string `json:"sub"`
    IsSuperadmin  bool   `json:"is_superadmin"`
    jwt.RegisteredClaims
}

const CtxUserID = "user_id"
const CtxIsSuper = "is_super"

func RequireAuth(secret string) gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenStr := ""
        hdr := c.GetHeader("Authorization")
        if strings.HasPrefix(strings.ToLower(hdr), "bearer ") {
            tokenStr = strings.TrimSpace(hdr[7:])
        }
        if tokenStr == "" {
            if ck, err := c.Cookie("auth_token"); err == nil {
                tokenStr = ck
            }
        }
        if tokenStr == "" {
            basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing token")
            c.Abort()
            return
        }
        token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
            return []byte(secret), nil
        })
        if err != nil || !token.Valid {
            basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token")
            c.Abort()
            return
        }
        claims := token.Claims.(*UserClaims)
        c.Set(CtxUserID, claims.Sub)
        c.Set(CtxIsSuper, claims.IsSuperadmin)
        c.Next()
    }
}

func IsSuper(c *gin.Context) bool {
    v, ok := c.Get(CtxIsSuper)
    if !ok {
        return false
    }
    b, _ := v.(bool)
    return b
}

// RequirePerm checks for a specific permission, superadmin always allowed.
func RequirePerm(db *gorm.DB, perm string) gin.HandlerFunc {
    return func(c *gin.Context) {
        if IsSuper(c) {
            c.Next()
            return
        }
        uidVal, ok := c.Get(CtxUserID)
        if !ok {
            basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing user")
            c.Abort()
            return
        }
        var count int64
        db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ?", uidVal, perm).Scan(&count)
        if count == 0 {
            basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "permission denied")
            c.Abort()
            return
        }
        c.Next()
    }
}

func CORS(origins []string) gin.HandlerFunc {
    allowed := map[string]struct{}{}
    for _, o := range origins {
        o = strings.TrimSpace(o)
        if o != "" {
            allowed[o] = struct{}{}
        }
    }
    return func(c *gin.Context) {
        origin := c.GetHeader("Origin")
        if origin != "" {
            if len(allowed) == 0 {
                c.Header("Access-Control-Allow-Origin", origin)
            } else if _, ok := allowed[origin]; ok {
                c.Header("Access-Control-Allow-Origin", origin)
            }
            c.Header("Access-Control-Allow-Credentials", "true")
            c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        }
        if c.Request.Method == http.MethodOptions {
            c.AbortWithStatus(http.StatusNoContent)
            return
        }
        c.Next()
    }
}
