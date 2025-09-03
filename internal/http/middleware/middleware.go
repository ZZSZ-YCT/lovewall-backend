package middleware

import (
    "net/http"
    "strings"
    "sync"
    "time"

    basichttp "lovewall/internal/http"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
    "go.uber.org/zap"
    "gorm.io/gorm"
    "golang.org/x/time/rate"
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
        db.Raw("SELECT COUNT(1) FROM user_permissions WHERE user_id = ? AND permission = ? AND deleted_at IS NULL", uidVal, perm).Scan(&count)
        if count == 0 {
            basichttp.Fail(c, http.StatusForbidden, "FORBIDDEN", "permission denied")
            c.Abort()
            return
        }
        c.Next()
    }
}

func CORS() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Always set CORS headers
        c.Header("Access-Control-Allow-Origin", "*")
        c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With, Accept, Origin")
        c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD")
        c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Type")
        c.Header("Access-Control-Max-Age", "86400")
        
        if c.Request.Method == http.MethodOptions {
            c.AbortWithStatus(http.StatusNoContent)
            return
        }
        c.Next()
    }
}

// Rate limiting
type visitor struct {
    limiter  *rate.Limiter
    lastSeen time.Time
}

type rateLimitStore struct {
    visitors map[string]*visitor
    mu       sync.Mutex
}

func (s *rateLimitStore) addVisitor(ip string, r rate.Limit, b int) *rate.Limiter {
    s.mu.Lock()
    defer s.mu.Unlock()

    v, exists := s.visitors[ip]
    if !exists {
        limiter := rate.NewLimiter(r, b)
        s.visitors[ip] = &visitor{limiter, time.Now()}
        return limiter
    }

    v.lastSeen = time.Now()
    return v.limiter
}

func (s *rateLimitStore) cleanup() {
    for {
        time.Sleep(time.Minute)
        s.mu.Lock()
        for ip, v := range s.visitors {
            if time.Since(v.lastSeen) > 3*time.Minute {
                delete(s.visitors, ip)
            }
        }
        s.mu.Unlock()
    }
}

var store = &rateLimitStore{
    visitors: make(map[string]*visitor),
}

func init() {
    go store.cleanup()
}

func RateLimit(rps int, burst int) gin.HandlerFunc {
    return func(c *gin.Context) {
        limiter := store.addVisitor(c.ClientIP(), rate.Limit(rps), burst)
        if !limiter.Allow() {
            basichttp.Fail(c, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded")
            c.Abort()
            return
        }
        c.Next()
    }
}
