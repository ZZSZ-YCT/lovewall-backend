-- Data Repair Script for Count Inconsistencies
-- Run this script ONCE after deploying the follow/block/counting fixes
-- This script is idempotent and safe to re-run

-- 1) Fix reply_count for all posts
UPDATE posts
SET reply_count = (
    SELECT COUNT(*) FROM posts r
    WHERE r.reply_to_id = posts.id
      AND r.deleted_at IS NULL
      AND r.status = 0
)
WHERE deleted_at IS NULL;

-- 2) Fix repost_count for all posts
UPDATE posts
SET repost_count = (
    SELECT COUNT(*) FROM posts r
    WHERE r.repost_of_id = posts.id
      AND r.deleted_at IS NULL
      AND r.status = 0
)
WHERE deleted_at IS NULL;

-- 3) Fix quote_count for all posts
UPDATE posts
SET quote_count = (
    SELECT COUNT(*) FROM posts r
    WHERE r.quote_of_id = posts.id
      AND r.deleted_at IS NULL
      AND r.status = 0
)
WHERE deleted_at IS NULL;

-- 4) Fix like_count for all posts
UPDATE posts
SET like_count = (
    SELECT COUNT(*) FROM post_likes
    WHERE post_likes.post_id = posts.id
      AND post_likes.deleted_at IS NULL
)
WHERE deleted_at IS NULL;

-- 5) Sync comment_count with reply_count (for top-level posts only)
-- This ensures migrated comment data is reflected correctly
UPDATE posts
SET comment_count = reply_count
WHERE reply_to_id IS NULL AND deleted_at IS NULL;

-- 6) Fix follower_count for all users
UPDATE users
SET follower_count = (
    SELECT COUNT(*) FROM user_follows
    WHERE following_id = users.id AND deleted_at IS NULL
)
WHERE deleted_at IS NULL;

-- 7) Fix following_count for all users
UPDATE users
SET following_count = (
    SELECT COUNT(*) FROM user_follows
    WHERE follower_id = users.id AND deleted_at IS NULL
)
WHERE deleted_at IS NULL;

-- 8) Clean up orphaned follow relationships (pointing to deleted users)
-- This removes follow relationships where either user is soft-deleted
DELETE FROM user_follows
WHERE follower_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL)
   OR following_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL);

-- 9) Clean up orphaned block relationships (pointing to deleted users)
DELETE FROM user_blocks
WHERE blocker_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL)
   OR blocked_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL);

-- 10) Clean up orphaned likes (pointing to deleted posts)
DELETE FROM post_likes
WHERE post_id IN (SELECT id FROM posts WHERE deleted_at IS NOT NULL);

-- 11) Clean up orphaned mentions (pointing to deleted posts or users)
DELETE FROM post_mentions
WHERE post_id IN (SELECT id FROM posts WHERE deleted_at IS NOT NULL)
   OR mentioned_user_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL);

-- Verification queries (run these to check results)
-- SELECT COUNT(*) as total_posts,
--        SUM(reply_count) as total_replies,
--        SUM(repost_count) as total_reposts,
--        SUM(quote_count) as total_quotes,
--        SUM(like_count) as total_likes
-- FROM posts WHERE deleted_at IS NULL;

-- SELECT COUNT(*) as total_users,
--        SUM(follower_count) as total_follower_relations,
--        SUM(following_count) as total_following_relations
-- FROM users WHERE deleted_at IS NULL;

-- Note: total_follower_relations should equal total_following_relations
-- as they count the same relationships from different perspectives
