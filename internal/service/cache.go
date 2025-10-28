package service

import (
	"container/list"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"lovewall/internal/config"
)

// Cache defines the minimal cache operations we rely on across handlers.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, keys ...string) error
	Healthy() bool
}

type cacheManager struct {
	redis        *redis.Client
	memory       *memoryCache
	logger       *zap.Logger
	perfWarn     time.Duration
	redisEnabled bool
}

// NewCacheManager initialises a cache layer backed by Redis with an in-memory
// fallback. Redis connectivity failures are logged and automatically fall back
// to memory-only caching.
func NewCacheManager(cfg *config.Config) Cache {
	logger := zap.L()
	maxEntries := cfg.CacheMaxEntries
	if maxEntries <= 0 {
		maxEntries = 1024
	}

	mgr := &cacheManager{
		memory:   newMemoryCache(maxEntries),
		logger:   logger,
		perfWarn: cfg.CachePerfWarnThreshold,
	}

	if cfg.RedisEnabled && cfg.RedisAddr != "" {
		opts := &redis.Options{
			Addr:         cfg.RedisAddr,
			Password:     cfg.RedisPassword,
			DB:           cfg.RedisDB,
			DialTimeout:  cfg.RedisDialTimeout,
			ReadTimeout:  cfg.RedisReadTimeout,
			WriteTimeout: cfg.RedisWriteTimeout,
		}
		if cfg.RedisUseTLS {
			opts.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}
		client := redis.NewClient(opts)
		ctx, cancel := context.WithTimeout(context.Background(), opts.DialTimeout)
		if opts.DialTimeout <= 0 {
			ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		}
		defer cancel()
		if err := client.Ping(ctx).Err(); err != nil {
			logger.Warn("redis unavailable, using in-memory cache only", zap.Error(err))
			_ = client.Close()
		} else {
			logger.Info("redis cache initialised", zap.String("addr", cfg.RedisAddr))
			mgr.redis = client
			mgr.redisEnabled = true
		}
	} else if cfg.RedisEnabled {
		logger.Warn("redis requested via config but REDIS_ADDR missing, using in-memory cache only")
	}

	return mgr
}

func (c *cacheManager) Healthy() bool {
	return c != nil && c.redisEnabled
}

func (c *cacheManager) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if key == "" {
		return nil, false, errors.New("cache key must not be empty")
	}
	start := time.Now()
	if c.redis != nil {
		val, err := c.redis.Get(ctx, key).Bytes()
		if err == nil {
			ttl := c.redis.TTL(ctx, key)
			if ttlErr := ttl.Err(); ttlErr == nil {
				if t := ttl.Val(); t > 0 {
					c.memory.Set(key, val, t)
				}
			}
			c.observe("redis_get", start, nil)
			return val, true, nil
		}
		if !errors.Is(err, redis.Nil) {
			c.logger.Warn("redis get failed, falling back to memory", zap.String("key", anonymiseKey(key)), zap.Error(err))
			c.observe("redis_get_error", start, err)
		} else {
			c.observe("redis_get_miss", start, nil)
		}
	}

	val, ok := c.memory.Get(key)
	if ok {
		c.observe("memory_get", start, nil)
		return val, true, nil
	}
	c.observe("memory_get_miss", start, nil)
	return nil, false, nil
}

func (c *cacheManager) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" {
		return errors.New("cache key must not be empty")
	}
	if ttl <= 0 {
		return nil
	}
	start := time.Now()
	c.memory.Set(key, value, ttl)
	if c.redis == nil {
		c.observe("memory_set_only", start, nil)
		return nil
	}
	if err := c.redis.Set(ctx, key, value, ttl).Err(); err != nil {
		c.logger.Warn("redis set failed, keeping memory cache", zap.String("key", anonymiseKey(key)), zap.Error(err))
		c.observe("redis_set_error", start, err)
		return err
	}
	c.observe("redis_set", start, nil)
	return nil
}

func (c *cacheManager) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	start := time.Now()
	for _, key := range keys {
		if key == "" {
			continue
		}
		c.memory.Delete(key)
	}
	if c.redis == nil {
		c.observe("memory_del_only", start, nil)
		return nil
	}
	if err := c.redis.Del(ctx, keys...).Err(); err != nil && !errors.Is(err, redis.Nil) {
		c.logger.Warn("redis delete failed", zap.Strings("keys", anonymiseKeys(keys)), zap.Error(err))
		c.observe("redis_del_error", start, err)
		return err
	}
	c.observe("redis_del", start, nil)
	return nil
}

func (c *cacheManager) observe(op string, start time.Time, err error) {
	if c.logger == nil || c.perfWarn <= 0 {
		return
	}
	elapsed := time.Since(start)
	if err != nil {
		c.logger.Warn("cache operation error", zap.String("op", op), zap.Duration("duration", elapsed), zap.Error(err))
		return
	}
	if elapsed >= c.perfWarn {
		c.logger.Info("cache operation slow", zap.String("op", op), zap.Duration("duration", elapsed))
	}
}

func anonymiseKey(key string) string {
	sum := sha1.Sum([]byte(key))
	return hex.EncodeToString(sum[:8])
}

func anonymiseKeys(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "" {
			continue
		}
		out = append(out, anonymiseKey(k))
	}
	return out
}

type memoryCache struct {
	mu         sync.Mutex
	items      map[string]*list.Element
	ll         *list.List
	maxEntries int
}

type memoryEntry struct {
	key    string
	value  []byte
	expire time.Time
}

func newMemoryCache(maxEntries int) *memoryCache {
	return &memoryCache{
		items:      make(map[string]*list.Element),
		ll:         list.New(),
		maxEntries: maxEntries,
	}
}

func (m *memoryCache) Set(key string, value []byte, ttl time.Duration) {
	if ttl <= 0 || key == "" {
		return
	}
	expire := time.Now().Add(ttl)
	m.mu.Lock()
	defer m.mu.Unlock()
	if elem, ok := m.items[key]; ok {
		entry := elem.Value.(*memoryEntry)
		entry.value = append(entry.value[:0], value...)
		entry.expire = expire
		m.ll.MoveToFront(elem)
		return
	}
	entry := &memoryEntry{
		key:    key,
		value:  append([]byte(nil), value...),
		expire: expire,
	}
	elem := m.ll.PushFront(entry)
	m.items[key] = elem
	m.evictExpiredLocked()
	if m.maxEntries > 0 && m.ll.Len() > m.maxEntries {
		m.evictOldestLocked()
	}
}

func (m *memoryCache) Get(key string) ([]byte, bool) {
	if key == "" {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	elem, ok := m.items[key]
	if !ok {
		return nil, false
	}
	entry := elem.Value.(*memoryEntry)
	if time.Now().After(entry.expire) {
		m.removeElementLocked(elem)
		return nil, false
	}
	m.ll.MoveToFront(elem)
	return append([]byte(nil), entry.value...), true
}

func (m *memoryCache) Delete(key string) {
	if key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	elem, ok := m.items[key]
	if !ok {
		return
	}
	m.removeElementLocked(elem)
}

func (m *memoryCache) evictExpiredLocked() {
	now := time.Now()
	for elem := m.ll.Back(); elem != nil; {
		prev := elem.Prev()
		entry := elem.Value.(*memoryEntry)
		if entry.expire.After(now) {
			break
		}
		m.removeElementLocked(elem)
		elem = prev
	}
}

func (m *memoryCache) evictOldestLocked() {
	elem := m.ll.Back()
	if elem != nil {
		m.removeElementLocked(elem)
	}
}

func (m *memoryCache) removeElementLocked(elem *list.Element) {
	entry := elem.Value.(*memoryEntry)
	delete(m.items, entry.key)
	m.ll.Remove(elem)
}
