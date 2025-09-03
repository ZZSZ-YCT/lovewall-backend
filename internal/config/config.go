package config

import (
    "crypto/rand"
    "encoding/hex"
    "os"
    "strconv"
)

type Config struct {
    Port            int
    DBDriver        string
    DBDsn           string
    JWTSecret       string
    JWTTTL          int64
    RefreshTTL      int64
    CookieName      string
    UploadDir       string
    UploadBaseURL   string
    MaxUploadMB     int64
    AdminInitUser   string
    AdminInitPass   string
    RateLimitRPS    int
    RateLimitBurst  int
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
        Port:           getinti("PORT", 8000),
        DBDriver:       getenv("DB_DRIVER", "sqlite"),
        DBDsn:          getenv("DB_DSN", "./data/app.db"),
        JWTSecret:      jwtSecret,
        JWTTTL:         getint64("JWT_TTL", 86400),
        RefreshTTL:     getint64("REFRESH_TTL", 2592000),
        CookieName:     getenv("COOKIE_NAME", "auth_token"),
        UploadDir:      uploadDir,
        UploadBaseURL:  getenv("UPLOAD_BASE_URL", "/uploads"),
        MaxUploadMB:    getint64("MAX_UPLOAD_MB", 10),
        AdminInitUser:  getenv("ADMIN_INIT_USER", ""),
        AdminInitPass:  getenv("ADMIN_INIT_PASS", ""),
        RateLimitRPS:   getinti("RATE_LIMIT_RPS", 20),
        RateLimitBurst: getinti("RATE_LIMIT_BURST", 40),
    }
}

