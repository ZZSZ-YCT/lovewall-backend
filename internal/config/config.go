package config

import (
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
    AllowOrigins    string
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

func Load() *Config {
    return &Config{
        Port:           getinti("PORT", 8000),
        DBDriver:       getenv("DB_DRIVER", "sqlite"),
        DBDsn:          getenv("DB_DSN", "./data/app.db"),
        JWTSecret:      getenv("JWT_SECRET", ""),
        JWTTTL:         getint64("JWT_TTL", 86400),
        RefreshTTL:     getint64("REFRESH_TTL", 2592000),
        CookieName:     getenv("COOKIE_NAME", "auth_token"),
        UploadDir:      getenv("UPLOAD_DIR", "./data/uploads"),
        UploadBaseURL:  getenv("UPLOAD_BASE_URL", "/uploads"),
        MaxUploadMB:    getint64("MAX_UPLOAD_MB", 10),
        AdminInitUser:  getenv("ADMIN_INIT_USER", ""),
        AdminInitPass:  getenv("ADMIN_INIT_PASS", ""),
        AllowOrigins:   getenv("ALLOW_ORIGINS", ""),
        RateLimitRPS:   getinti("RATE_LIMIT_RPS", 20),
        RateLimitBurst: getinti("RATE_LIMIT_BURST", 40),
    }
}

