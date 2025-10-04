-- Permission System Migration Script
-- 将旧的8个权限迁移到新的6个颗粒度权限
-- 执行方式: sqlite3 lovewall.db < scripts/migrate_permissions.sql

-- 备份现有权限表
CREATE TABLE IF NOT EXISTS user_permissions_backup AS SELECT * FROM user_permissions WHERE deleted_at IS NULL;

-- 1. 将 HIDE_POST, DELETE_POST, EDIT_POST 合并为 MANAGE_POSTS
-- 查找拥有任意旧帖子权限的用户,给他们分配 MANAGE_POSTS
INSERT OR IGNORE INTO user_permissions (id, user_id, permission, created_at, updated_at, deleted_at)
SELECT
    lower(hex(randomblob(16))),  -- 生成UUID
    DISTINCT user_id,
    'MANAGE_POSTS',
    datetime('now'),
    datetime('now'),
    NULL
FROM user_permissions
WHERE permission IN ('HIDE_POST', 'DELETE_POST', 'EDIT_POST')
  AND deleted_at IS NULL
GROUP BY user_id;

-- 2. 将 PIN_POST, FEATURE_POST 合并为 MANAGE_FEATURED
INSERT OR IGNORE INTO user_permissions (id, user_id, permission, created_at, updated_at, deleted_at)
SELECT
    lower(hex(randomblob(16))),
    DISTINCT user_id,
    'MANAGE_FEATURED',
    datetime('now'),
    datetime('now'),
    NULL
FROM user_permissions
WHERE permission IN ('PIN_POST', 'FEATURE_POST')
  AND deleted_at IS NULL
GROUP BY user_id;

-- 3. 软删除所有旧权限记录
UPDATE user_permissions
SET deleted_at = datetime('now')
WHERE permission IN ('HIDE_POST', 'DELETE_POST', 'EDIT_POST', 'PIN_POST', 'FEATURE_POST')
  AND deleted_at IS NULL;

-- 验证查询: 检查迁移结果
-- SELECT user_id, GROUP_CONCAT(permission, ', ') as permissions
-- FROM user_permissions
-- WHERE deleted_at IS NULL
-- GROUP BY user_id;

-- 新权限体系说明:
-- MANAGE_POSTS       - 帖子管理(审核/删除/隐藏)
-- MANAGE_COMMENTS    - 评论管理(隐藏/删除)
-- MANAGE_USERS       - 用户管理(修改信息/封禁)
-- MANAGE_FEATURED    - 精华管理(置顶/精华)
-- MANAGE_ANNOUNCEMENTS - 公告管理(创建/删除)
-- MANAGE_TAGS        - 标签管理(CRUD + 兑换码)
