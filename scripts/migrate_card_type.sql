-- 添加card_type字段,默认值为'confession'
ALTER TABLE posts ADD COLUMN card_type TEXT NOT NULL DEFAULT 'confession';
-- 创建索引
CREATE INDEX idx_posts_card_type ON posts(card_type);
-- 将所有现有数据标记为表白卡
UPDATE posts SET card_type = 'confession' WHERE card_type IS NULL OR card_type = '';
