package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port           int
	DBDriver       string
	DBDsn          string
	JWTSecret      string
	JWTTTL         int64
	RefreshTTL     int64
	CookieName     string
	UploadDir      string
	UploadBaseURL  string
	MaxUploadMB    int64
	AdminInitUser  string
	AdminInitPass  string
	RateLimitRPS   int
	RateLimitBurst int
	AIBaseURL      string
	AIAPIKey       string
	AIModel        string
	AIRateRPS      int
	AIRateBurst    int
	// Behavior rate-limits (per device/fingerprint/browser)
	ActionPostCount        int // default 5
	ActionPostWindowSec    int // default 60s
	ActionCommentCount     int // default 3
	ActionCommentWindowSec int // default 10s
	// Account/IP quotas
	QuotaPostsPerUserPerDay     int // default 5
	QuotaPostsPerIPPerDay       int // default 5
	QuotaCommentsPerUserPerHour int // default 10
	QuotaCommentsPerIPPerHour   int // default 10
	MaxPostChars                int // default 2000
	MaxCommentChars             int // default 500
	// Geetest captcha
	GeetestCaptchaID  string // Geetest public key (captcha_id)
	GeetestCaptchaKey string // Geetest private key (captcha_key)
	// Cache / Redis
	RedisEnabled           bool
	RedisAddr              string
	RedisPassword          string
	RedisDB                int
	RedisUseTLS            bool
	RedisDialTimeout       time.Duration
	RedisReadTimeout       time.Duration
	RedisWriteTimeout      time.Duration
	CacheMaxEntries        int
	CacheUserTTL           time.Duration
	CacheUserListTTL       time.Duration
	CachePerfWarnThreshold time.Duration
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getinti(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func getint64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
	}
	return def
}

func getbool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(strings.ToLower(v)); err == nil {
			return b
		}
	}
	return def
}

func getdurationMS(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if ms, err := strconv.Atoi(v); err == nil {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return def
}

func generateJWTSecret() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic("failed to generate JWT secret: " + err.Error())
	}
	return hex.EncodeToString(bytes)
}

func Load() *Config {
	jwtSecret := getenv("JWT_SECRET", "")
	if jwtSecret == "" || jwtSecret == "change_me" {
		jwtSecret = generateJWTSecret()
	}

	uploadDir := getenv("UPLOAD_DIR", "./data/uploads")

	// Create upload directory if it doesn't exist
	if uploadDir != "" {
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			panic("failed to create upload directory " + uploadDir + ": " + err.Error())
		}
	}

	redisDialTimeout := getdurationMS("REDIS_DIAL_TIMEOUT_MS", 1500*time.Millisecond)
	if redisDialTimeout <= 0 {
		redisDialTimeout = 1500 * time.Millisecond
	}
	redisReadTimeout := getdurationMS("REDIS_READ_TIMEOUT_MS", 800*time.Millisecond)
	if redisReadTimeout <= 0 {
		redisReadTimeout = 800 * time.Millisecond
	}
	redisWriteTimeout := getdurationMS("REDIS_WRITE_TIMEOUT_MS", 800*time.Millisecond)
	if redisWriteTimeout <= 0 {
		redisWriteTimeout = 800 * time.Millisecond
	}
	cacheUserTTL := getdurationMS("CACHE_USER_TTL_MS", 30*time.Minute)
	if cacheUserTTL <= 0 {
		cacheUserTTL = 30 * time.Minute
	}
	cacheUserListTTL := getdurationMS("CACHE_USER_LIST_TTL_MS", 5*time.Minute)
	if cacheUserListTTL <= 0 {
		cacheUserListTTL = 5 * time.Minute
	}
	cachePerfWarn := getdurationMS("CACHE_PERF_WARN_MS", 200*time.Millisecond)
	if cachePerfWarn <= 0 {
		cachePerfWarn = 200 * time.Millisecond
	}

	return &Config{
		Port:                        getinti("PORT", 8000),
		DBDriver:                    getenv("DB_DRIVER", "sqlite"),
		DBDsn:                       getenv("DB_DSN", "./data/app.db"),
		JWTSecret:                   jwtSecret,
		JWTTTL:                      getint64("JWT_TTL", 86400),
		RefreshTTL:                  getint64("REFRESH_TTL", 2592000),
		CookieName:                  getenv("COOKIE_NAME", "auth_token"),
		UploadDir:                   uploadDir,
		UploadBaseURL:               getenv("UPLOAD_BASE_URL", "/uploads"),
		MaxUploadMB:                 getint64("MAX_UPLOAD_MB", 10),
		AdminInitUser:               getenv("ADMIN_INIT_USER", ""),
		AdminInitPass:               getenv("ADMIN_INIT_PASS", ""),
		RateLimitRPS:                getinti("RATE_LIMIT_RPS", 20),
		RateLimitBurst:              getinti("RATE_LIMIT_BURST", 40),
		AIBaseURL:                   getenv("AI_BASE_URL", ""),
		AIAPIKey:                    getenv("AI_API_KEY", ""),
		AIModel:                     getenv("AI_MODEL", ""),
		AIRateRPS:                   getinti("AI_RATE_RPS", 3),
		AIRateBurst:                 getinti("AI_RATE_BURST", 3),
		ActionPostCount:             getinti("ACTION_POST_COUNT", 5),
		ActionPostWindowSec:         getinti("ACTION_POST_WINDOW_SEC", 60),
		ActionCommentCount:          getinti("ACTION_COMMENT_COUNT", 3),
		ActionCommentWindowSec:      getinti("ACTION_COMMENT_WINDOW_SEC", 10),
		QuotaPostsPerUserPerDay:     getinti("QUOTA_POSTS_PER_USER_PER_DAY", 5),
		QuotaPostsPerIPPerDay:       getinti("QUOTA_POSTS_PER_IP_PER_DAY", 5),
		QuotaCommentsPerUserPerHour: getinti("QUOTA_COMMENTS_PER_USER_PER_HOUR", 10),
		QuotaCommentsPerIPPerHour:   getinti("QUOTA_COMMENTS_PER_IP_PER_HOUR", 10),
		MaxPostChars:                getinti("MAX_POST_CHARS", 2000),
		MaxCommentChars:             getinti("MAX_COMMENT_CHARS", 500),
		GeetestCaptchaID:            getenv("GEETEST_CAPTCHA_ID", ""),
		GeetestCaptchaKey:           getenv("GEETEST_CAPTCHA_KEY", ""),
		RedisEnabled:                getbool("REDIS_ENABLED", false),
		RedisAddr:                   getenv("REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword:               getenv("REDIS_PASSWORD", ""),
		RedisDB:                     getinti("REDIS_DB", 0),
		RedisUseTLS:                 getbool("REDIS_USE_TLS", false),
		RedisDialTimeout:            redisDialTimeout,
		RedisReadTimeout:            redisReadTimeout,
		RedisWriteTimeout:           redisWriteTimeout,
		CacheMaxEntries:             getinti("CACHE_MAX_ENTRIES", 2048),
		CacheUserTTL:                cacheUserTTL,
		CacheUserListTTL:            cacheUserListTTL,
		CachePerfWarnThreshold:      cachePerfWarn,
	}
}
