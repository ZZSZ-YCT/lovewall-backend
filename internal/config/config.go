package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
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

func generateJWTSecret() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic("failed to generate JWT secret: " + err.Error())
	}
	return hex.EncodeToString(bytes)
}

func Load() *Config {
	jwtSecret := getenv("JWT_SECRET", "")
	if jwtSecret == "" || jwtSecret == "please_change_me" {
		jwtSecret = generateJWTSecret()
	}

	uploadDir := getenv("UPLOAD_DIR", "./data/uploads")

	// Create upload directory if it doesn't exist
	if uploadDir != "" {
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			panic("failed to create upload directory " + uploadDir + ": " + err.Error())
		}
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
	}
}
