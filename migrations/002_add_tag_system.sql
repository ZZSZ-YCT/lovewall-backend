-- Add Tag system tables

-- 创建标签表
CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    background_color TEXT NOT NULL,
    text_color TEXT NOT NULL,
    description TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    metadata TEXT,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    deleted_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_tags_deleted ON tags(deleted_at);
CREATE INDEX IF NOT EXISTS idx_tags_active ON tags(is_active);

-- 创建兑换码表
CREATE TABLE IF NOT EXISTS redemption_codes (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    tag_id TEXT NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0,
    used_by TEXT,
    used_at DATETIME,
    expires_at DATETIME,
    batch_id TEXT,
    metadata TEXT,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    deleted_at DATETIME,
    FOREIGN KEY(tag_id) REFERENCES tags(id),
    FOREIGN KEY(used_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_redemption_codes_deleted ON redemption_codes(deleted_at);
CREATE INDEX IF NOT EXISTS idx_redemption_codes_used ON redemption_codes(is_used);
CREATE INDEX IF NOT EXISTS idx_redemption_codes_tag ON redemption_codes(tag_id);
CREATE INDEX IF NOT EXISTS idx_redemption_codes_batch ON redemption_codes(batch_id);
CREATE INDEX IF NOT EXISTS idx_redemption_codes_expires ON redemption_codes(expires_at);

-- 创建用户标签表
CREATE TABLE IF NOT EXISTS user_tags (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    tag_id TEXT NOT NULL,
    obtained_at DATETIME NOT NULL DEFAULT (datetime('now')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    deleted_at DATETIME,
    UNIQUE(user_id, tag_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(tag_id) REFERENCES tags(id)
);

CREATE INDEX IF NOT EXISTS idx_user_tags_deleted ON user_tags(deleted_at);
CREATE INDEX IF NOT EXISTS idx_user_tags_user ON user_tags(user_id);
CREATE INDEX IF NOT EXISTS idx_user_tags_active ON user_tags(is_active);