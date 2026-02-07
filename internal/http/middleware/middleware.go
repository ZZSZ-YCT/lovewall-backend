package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	basichttp "lovewall/internal/http"
	"lovewall/internal/model"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
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

// RequestDBLogger persists per-request logs to database. Not exposed via API.
func RequestDBLogger(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start).Milliseconds()
		method := c.Request.Method
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery
		status := c.Writer.Status()
		ip := c.ClientIP()
		ua := c.Request.UserAgent()
		var userIDPtr *string
		if v, ok := c.Get(CtxUserID); ok {
			if s, ok2 := v.(string); ok2 {
				userIDPtr = &s
			}
		}
		trace := c.Writer.Header().Get("X-Trace-ID")
		if trace == "" {
			trace = c.GetHeader("X-Trace-ID")
		}

		q := rawQuery
		ipCopy := ip
		uaCopy := ua
		trCopy := trace
		rec := &model.RequestLog{
			UserID:     userIDPtr,
			Method:     method,
			Path:       path,
			Status:     status,
			DurationMs: duration,
		}
		if q != "" {
			rec.Query = &q
		}
		if ipCopy != "" {
			rec.IP = &ipCopy
		}
		if uaCopy != "" {
			rec.UserAgent = &uaCopy
		}
		if trCopy != "" {
			rec.TraceID = &trCopy
		}
		enqueueRequestLog(rec)
	}
}

// ---- Async request log writer to reduce SQLite write contention ----
var reqLogCh = make(chan *model.RequestLog, 10000)

func enqueueRequestLog(rec *model.RequestLog) {
	select {
	case reqLogCh <- rec:
	default:
		// drop if backlog is full to avoid blocking hot path
	}
}

func StartRequestLogWriter(db *gorm.DB) {
	go func() {
		for rec := range reqLogCh {
			// ignore error to avoid blocking; SQLite busy will be retried by busy_timeout
			_ = db.Create(rec).Error
		}
	}()
}

type UserClaims struct {
	Sub          string `json:"sub"`
	IsSuperadmin bool   `json:"is_superadmin"`
	jwt.RegisteredClaims
}

const CtxUserID = "user_id"
const CtxIsSuper = "is_super"
const CtxIsAdmin = "is_admin"
const CtxTokenStr = "token_str"
const CtxTokenExp = "token_exp"
const CtxTokenJTI = "token_jti"

// --- Token blacklist (simple in-memory with TTL) ---
type tokenBlacklist struct {
	mu     sync.RWMutex
	tokens map[string]time.Time // token string -> expires at
}

var bl = &tokenBlacklist{tokens: map[string]time.Time{}}

func init() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			bl.mu.Lock()
			for t, exp := range bl.tokens {
				if now.After(exp) {
					delete(bl.tokens, t)
				}
			}
			bl.mu.Unlock()
		}
	}()
}

// AddTokenToBlacklist marks a token as revoked until exp time.
func AddTokenToBlacklist(token string, exp time.Time) {
	bl.mu.Lock()
	bl.tokens[token] = exp
	bl.mu.Unlock()
}

// IsTokenBlacklisted checks whether token is revoked.
func IsTokenBlacklisted(token string) bool {
	bl.mu.RLock()
	exp, ok := bl.tokens[token]
	bl.mu.RUnlock()
	if !ok {
		return false
	}
	// If somehow past exp, treat as not blacklisted (cleanup will remove)
	return time.Now().Before(exp)
}

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
		if IsTokenBlacklisted(tokenStr) {
			basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "token revoked")
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
		if claims.ExpiresAt != nil {
			c.Set(CtxTokenExp, claims.ExpiresAt.Time)
		}
		if claims.ID != "" {
			c.Set(CtxTokenJTI, claims.ID)
		}
		c.Set(CtxTokenStr, tokenStr)
		c.Next()
	}
}

// IsSuperCached reads superadmin status from JWT (cached, may be stale)
func IsSuperCached(c *gin.Context) bool {
	v, ok := c.Get(CtxIsSuper)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// IsSuper checks superadmin status from database (realtime, always accurate)
func IsSuper(c *gin.Context, db *gorm.DB) bool {
	uidVal, ok := c.Get(CtxUserID)
	if !ok {
		return false
	}
	uid, _ := uidVal.(string)
	var u model.User
	if err := db.Select("is_superadmin").First(&u, "id = ? AND deleted_at IS NULL", uid).Error; err != nil {
		return false
	}
	if !u.IsSuperadmin {
		return false
	}
	return true
}

// RequirePerm checks for a specific permission, superadmin always allowed.
func RequirePerm(db *gorm.DB, perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if IsSuper(c, db) {
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

func isAdminUser(c *gin.Context, db *gorm.DB) bool {
	if v, ok := c.Get(CtxIsAdmin); ok {
		if b, ok2 := v.(bool); ok2 {
			return b
		}
	}
	uidVal, ok := c.Get(CtxUserID)
	if !ok {
		return false
	}
	uid, _ := uidVal.(string)
	var u model.User
	if err := db.Select("is_superadmin").First(&u, "id = ? AND deleted_at IS NULL", uid).Error; err != nil {
		return false
	}
	if u.IsSuperadmin {
		c.Set(CtxIsAdmin, true)
		return true
	}
	var cnt int64
	db.Model(&model.UserPermission{}).Where("user_id = ? AND deleted_at IS NULL", uid).Count(&cnt)
	isAdmin := cnt > 0
	c.Set(CtxIsAdmin, isAdmin)
	return isAdmin
}

func CORS(allowedOrigins []string) gin.HandlerFunc {
	// Build a set for fast origin lookup
	allowAll := false
	originSet := make(map[string]bool)

	for _, origin := range allowedOrigins {
		if origin == "*" {
			allowAll = true
			break
		}
		originSet[origin] = true
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Determine if this origin is allowed
		originAllowed := false
		if allowAll {
			originAllowed = true
		} else if strings.TrimSpace(origin) != "" && originSet[origin] {
			originAllowed = true
		}

		// Set CORS headers only for allowed origins
		if originAllowed {
			if allowAll && strings.TrimSpace(origin) != "" {
				// Echo the origin for wildcard mode
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			} else if allowAll {
				// No origin header, use wildcard
				c.Header("Access-Control-Allow-Origin", "*")
			} else {
				// Whitelist mode: echo the specific allowed origin
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			}

			// Only allow credentials for non-wildcard origins
			if !allowAll || strings.TrimSpace(origin) != "" {
				c.Header("Access-Control-Allow-Credentials", "true")
			}

			// Allow all requested headers
			if reqHdr := c.GetHeader("Access-Control-Request-Headers"); strings.TrimSpace(reqHdr) != "" {
				c.Header("Access-Control-Allow-Headers", reqHdr)
				c.Header("Vary", "Access-Control-Request-Headers")
			} else {
				c.Header("Access-Control-Allow-Headers", "*")
			}

			// Allow requested method or a broad default set
			if reqMethod := c.GetHeader("Access-Control-Request-Method"); strings.TrimSpace(reqMethod) != "" {
				c.Header("Access-Control-Allow-Methods", reqMethod)
				c.Header("Vary", "Access-Control-Request-Method")
			} else {
				c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD")
			}

			// Expose all headers to the client where supported
			c.Header("Access-Control-Expose-Headers", "*")
			c.Header("Access-Control-Max-Age", "86400")

			// CRITICAL: Prevent CDN/proxy caching of CORS headers with varying origins
			c.Header("Cache-Control", "no-store, must-revalidate")

			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
		} else {
			// Origin not allowed - reject preflight explicitly
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			// For actual requests, let it through but without CORS headers
			// (browser will block the response)
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
		// Never rate-limit CORS preflight requests
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		limiter := store.addVisitor(c.ClientIP(), rate.Limit(rps), burst)
		if !limiter.Allow() {
			basichttp.Fail(c, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}

// ---- Action rate limits (per client key) ----
type actionLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time // key -> timestamps
}

var actLimiter = &actionLimiter{hits: map[string][]time.Time{}}

// sanitizeID clamps length and allowed characters to avoid abuse via huge/invalid identifiers.
func sanitizeID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 128 {
		s = s[:128]
	}
	// allow alnum, dash, underscore, dot, colon
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == ':' {
			b = append(b, ch)
		}
	}
	return string(b)
}

// clientKey derives a stable key for a device/browser: prefer explicit headers,
// fall back to cookie, then to IP+UA.
func clientKey(c *gin.Context) string {
	if v := sanitizeID(c.GetHeader("X-Device-ID")); v != "" {
		return "dev:" + v
	}
	if v := sanitizeID(c.GetHeader("X-Fingerprint")); v != "" {
		return "fp:" + v
	}
	if ck, err := c.Cookie("device_id"); err == nil {
		if v := sanitizeID(ck); v != "" {
			return "ck:" + v
		}
	}
	return "ipua:" + c.ClientIP() + "|" + strings.TrimSpace(c.Request.UserAgent())
}

// LimitAction enforces at most `limit` requests within `window` for a given action name per client.
func LimitAction(action string, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := action + "|" + clientKey(c)
		now := time.Now()
		cutoff := now.Add(-window)
		actLimiter.mu.Lock()
		list := actLimiter.hits[key]
		// drop old
		i := 0
		for _, t := range list {
			if t.After(cutoff) {
				list[i] = t
				i++
			}
		}
		list = list[:i]
		if len(list) >= limit {
			actLimiter.mu.Unlock()
			basichttp.Fail(c, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests")
			c.Abort()
			return
		}
		list = append(list, now)
		actLimiter.hits[key] = list
		actLimiter.mu.Unlock()
		c.Next()
	}
}

// ValidateSessionAndUser ensures the JWT maps to a live session and the user is not banned.
func ValidateSessionAndUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract context set by RequireAuth
		uidVal, uidOK := c.Get(CtxUserID)
		jtiVal, jtiOK := c.Get(CtxTokenJTI)
		if !uidOK || !jtiOK {
			basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token")
			c.Abort()
			return
		}
		uid, _ := uidVal.(string)
		jti, _ := jtiVal.(string)

		// Load user including soft-deleted to distinguish deleted vs not-exist
		var u model.User
		if err := db.Unscoped().First(&u, "id = ?", uid).Error; err != nil {
			basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "user not found")
			c.Abort()
			return
		}
		// Soft-deleted user: surface dedicated marker to help frontend avoid generic errors
		if u.DeletedAt != nil {
			basichttp.FailWithExtras(c, http.StatusForbidden, "ACCOUNT_DELETED", "account has been deleted", gin.H{"is_deleted": true})
			c.Abort()
			return
		}
		// Banned user: surface reason if present
		if u.IsBanned {
			reason := "account has been banned"
			if u.BanReason != nil && *u.BanReason != "" {
				reason = *u.BanReason
			}
			basichttp.FailWithExtras(c, http.StatusForbidden, "BANNED", reason, gin.H{"banned": true, "ban_reason": reason})
			c.Abort()
			return
		}

		// Verify session exists
		var cnt int64
		db.Model(&model.UserSession{}).Where("user_id = ? AND jti = ?", uid, jti).Count(&cnt)
		if cnt == 0 {
			basichttp.Fail(c, http.StatusUnauthorized, "UNAUTHORIZED", "token revoked")
			c.Abort()
			return
		}

		isAdmin := u.IsSuperadmin
		if !isAdmin {
			var permCnt int64
			db.Model(&model.UserPermission{}).
				Where("user_id = ? AND deleted_at IS NULL", uid).
				Count(&permCnt)
			isAdmin = permCnt > 0
		}
		c.Set(CtxIsAdmin, isAdmin)
		c.Next()
	}
}

// Daily/Hourly quotas for posts/comments per user and per IP.
func EnforcePostDailyQuota(db *gorm.DB, perUser int, perIP int) gin.HandlerFunc {
	return func(c *gin.Context) {
		now := time.Now()
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		ip := c.ClientIP()
		uidVal, _ := c.Get(CtxUserID)
		uid := uidVal.(string)
		var cntUser int64
		db.Model(&model.Post{}).Where("author_id = ? AND deleted_at IS NULL AND created_at >= ?", uid, start).Count(&cntUser)
		if cntUser >= int64(perUser) {
			basichttp.Fail(c, http.StatusTooManyRequests, "RATE_LIMITED", "post daily quota exceeded")
			c.Abort()
			return
		}
		// count by IP using submission logs where action = post_create and metadata contains this IP
		var cntIP int64
		db.Model(&model.SubmissionLog{}).Where("action = ? AND created_at >= ? AND metadata LIKE ?", "post_create", start, "%\"ip\":\""+ip+"\"%").Count(&cntIP)
		if cntIP >= int64(perIP) {
			basichttp.Fail(c, http.StatusTooManyRequests, "RATE_LIMITED", "post daily quota exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}

func EnforceCommentHourlyQuota(db *gorm.DB, perUser int, perIP int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		uidVal, _ := c.Get(CtxUserID)
		uid := uidVal.(string)
		since := time.Now().Add(-1 * time.Hour)
		var cntUser int64
		db.Model(&model.Comment{}).Where("user_id = ? AND deleted_at IS NULL AND created_at >= ?", uid, since).Count(&cntUser)
		if cntUser >= int64(perUser) {
			basichttp.Fail(c, http.StatusTooManyRequests, "RATE_LIMITED", "comment hourly quota exceeded")
			c.Abort()
			return
		}
		var cntIP int64
		db.Model(&model.SubmissionLog{}).Where("action = ? AND created_at >= ? AND metadata LIKE ?", "comment_create", since, "%\"ip\":\""+ip+"\"%").Count(&cntIP)
		if cntIP >= int64(perIP) {
			basichttp.Fail(c, http.StatusTooManyRequests, "RATE_LIMITED", "comment hourly quota exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}
