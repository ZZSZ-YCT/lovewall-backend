package service

import (
	"context"
	"fmt"
	"html"
	"strings"

	"gorm.io/gorm"
	"lovewall/internal/model"
)

type task struct {
	kind string // "post" or "comment"
	id   string
}

var modCh = make(chan task, 10000)

func EnqueuePostModeration(id string) {
	select {
	case modCh <- task{kind: "post", id: id}:
	default:
	}
}
func EnqueueCommentModeration(id string) {
	select {
	case modCh <- task{kind: "comment", id: id}:
	default:
	}
}

type aiConfigProvider interface {
	GetAIBaseURL() string
	GetAIAPIKey() string
	GetAIModel() string
}

func StartModerationWorker(db *gorm.DB, cfg aiConfigProvider) {
	go func() {
		for t := range modCh {
			switch t.kind {
			case "post":
				moderatePostV2(db, cfg, t.id)
			case "comment":
				moderateCommentV2(db, cfg, t.id)
			}
		}
	}()
}

// ----- V2 scoring-based moderation -----
func moderatePostV2(db *gorm.DB, cfg aiConfigProvider, id string) {
	var p model.Post
	if err := db.First(&p, "id = ?", id).Error; err != nil {
		return
	}
	cardType := "confession"
	if p.CardType != nil {
		trimmed := strings.TrimSpace(*p.CardType)
		if trimmed != "" {
			cardType = strings.ToLower(trimmed)
		}
	}
	ctxText := "CardType:" + cardType + "\n作者:" + p.AuthorName + "\n对象:" + p.TargetName + "\n内容:" + p.Content
	res, _ := ModerateWithRetry(context.Background(), NewConfigAdapter(cfg.GetAIBaseURL(), cfg.GetAIAPIKey(), cfg.GetAIModel()), BuildPostPrompt(ctxText, cardType))
	score, msg := 95, ""
	if res != nil {
		score = res.Score
		msg = res.Msg
	}

	// Log AI moderation result
	contentPreview := p.Content
	if len(contentPreview) > 200 {
		contentPreview = contentPreview[:200] + "..."
	}

	if score <= 55 {
		// Log AI auto-delete decision
		LogAIModeration(db, "post", id, p.AuthorID, score, "auto_deleted", "auto_delete", msg, map[string]any{
			"content_preview": contentPreview,
			"author_name":     p.AuthorName,
			"target_name":     p.TargetName,
			"card_type":       cardType,
		})

		wasVisible := p.Status == 0

		tx := db.Begin()
		if tx.Error != nil {
			return
		}
		// Decrement parent counts if post was visible
		if wasVisible {
			if p.ReplyToID != nil && *p.ReplyToID != "" {
				if err := tx.Model(&model.Post{}).Where("id = ?", *p.ReplyToID).Update("reply_count", gorm.Expr("CASE WHEN reply_count > 0 THEN reply_count - 1 ELSE 0 END")).Error; err != nil {
					tx.Rollback()
					return
				}
			}
			if p.RepostOfID != nil && *p.RepostOfID != "" {
				if err := tx.Model(&model.Post{}).Where("id = ?", *p.RepostOfID).Update("repost_count", gorm.Expr("CASE WHEN repost_count > 0 THEN repost_count - 1 ELSE 0 END")).Error; err != nil {
					tx.Rollback()
					return
				}
			}
			if p.QuoteOfID != nil && *p.QuoteOfID != "" {
				if err := tx.Model(&model.Post{}).Where("id = ?", *p.QuoteOfID).Update("quote_count", gorm.Expr("CASE WHEN quote_count > 0 THEN quote_count - 1 ELSE 0 END")).Error; err != nil {
					tx.Rollback()
					return
				}
			}
		}
		if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.Comment{}).Error; err != nil {
			tx.Rollback()
			return
		}
		if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.PostImage{}).Error; err != nil {
			tx.Rollback()
			return
		}
		if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.PostLike{}).Error; err != nil {
			tx.Rollback()
			return
		}
		if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.PostMention{}).Error; err != nil {
			tx.Rollback()
			return
		}
		if err := tx.Unscoped().Where("post_id = ?", id).Delete(&model.PostView{}).Error; err != nil {
			tx.Rollback()
			return
		}
		if err := tx.Unscoped().Delete(&p).Error; err != nil {
			tx.Rollback()
			return
		}
		if err := tx.Commit().Error; err != nil {
			return
		}
		reason := msg
		if reason == "" {
			reason = "评分低于 56 分，已删除"
		}
		content := fmt.Sprintf(`<div class="notification-card">
  <h3>AI 审核未通过</h3>
  <p><strong>评分：</strong>%d（低于 56 分，已删除）</p>
  <p><strong>原因：</strong>%s</p>
  <div class="post-preview">
    <div class="post-preview__label">原帖内容</div>
    <pre class="post-preview__body" style="white-space: pre-wrap;">%s</pre>
  </div>
</div>`, score, html.EscapeString(reason), html.EscapeString(p.Content))
		Notify(db, p.AuthorID, "系统通知：帖子被删除", content, map[string]any{"post_id": p.ID})
		return
	}
	if score < 80 {
		// Log AI flag for review decision
		LogAIModeration(db, "post", id, p.AuthorID, score, "pending_review", "flag_for_review", msg, map[string]any{
			"content_preview": contentPreview,
			"author_name":     p.AuthorName,
			"target_name":     p.TargetName,
			"card_type":       cardType,
		})

		_ = db.Model(&model.Post{}).Where("id = ?", id).Updates(map[string]any{"status": 1, "audit_status": 1, "audit_msg": fmt.Sprintf("AI评分 %d：%s", score, msg), "manual_review_requested": true}).Error
		// Notify author to wait for admin review
		Notify(db, p.AuthorID, "AI 审核中：请等待管理员审核", "我们的自动审核系统无法验证帖子的合规性，请等待管理员审核。", map[string]any{"post_id": p.ID})

		// Collect reviewer IDs (superadmins + MANAGE_POSTS permission holders)
		reviewerIDs := map[string]struct{}{}
		var adminIDs []string
		db.Model(&model.User{}).Where("is_superadmin = 1 AND deleted_at IS NULL").Pluck("id", &adminIDs)
		for _, rid := range adminIDs {
			reviewerIDs[rid] = struct{}{}
		}
		perms := []string{"MANAGE_POSTS"}
		var upIDs []string
		db.Model(&model.UserPermission{}).Where("permission IN ? AND deleted_at IS NULL", perms).Pluck("user_id", &upIDs)
		for _, rid := range upIDs {
			reviewerIDs[rid] = struct{}{}
		}

		// Notify all reviewers with detailed info
		adminNotificationContent := fmt.Sprintf(`<div class="notification-card">
  <h3>AI 审核：需要人工复核</h3>
  <p><strong>AI 评分：</strong>%d / 100（待审核区间 56-79）</p>
  <p><strong>AI 原因：</strong>%s</p>
  <p><strong>帖子 ID：</strong>%s</p>
  <p><strong>表白对象：</strong>%s</p>
  <p><strong>发布者：</strong>%s</p>
  <div class="post-preview">
    <div class="post-preview__label">帖子内容</div>
    <pre class="post-preview__body" style="white-space: pre-wrap;">%s</pre>
  </div>
</div>`, score, html.EscapeString(msg), html.EscapeString(p.ID), html.EscapeString(p.TargetName), html.EscapeString(p.AuthorName), html.EscapeString(p.Content))

		for rid := range reviewerIDs {
			if rid == p.AuthorID {
				continue
			}
			Notify(db, rid, "AI 审核结果：需要人工复核", adminNotificationContent, map[string]any{"post_id": p.ID, "ai_score": score})
		}
		return
	}

	// Log AI auto-approve decision
	LogAIModeration(db, "post", id, p.AuthorID, score, "approved", "auto_approve", msg, map[string]any{
		"content_preview": contentPreview,
		"author_name":     p.AuthorName,
		"target_name":     p.TargetName,
	})

	wasHidden := p.Status != 0

	tx := db.Begin()
	if tx.Error != nil {
		return
	}

	if err := tx.Model(&model.Post{}).Where("id = ?", id).Updates(map[string]any{"status": 0, "audit_status": 0, "audit_msg": nil, "manual_review_requested": false}).Error; err != nil {
		tx.Rollback()
		return
	}

	// Only increment counts if post was previously hidden
	if wasHidden {
		// If this is a reply, increment parent's reply_count
		if p.ReplyToID != nil && *p.ReplyToID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.ReplyToID).Update("reply_count", gorm.Expr("reply_count + 1")).Error; err != nil {
				tx.Rollback()
				return
			}
		}
		// If this is a repost, increment parent's repost_count
		if p.RepostOfID != nil && *p.RepostOfID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.RepostOfID).Update("repost_count", gorm.Expr("repost_count + 1")).Error; err != nil {
				tx.Rollback()
				return
			}
		}
		// If this is a quote, increment parent's quote_count
		if p.QuoteOfID != nil && *p.QuoteOfID != "" {
			if err := tx.Model(&model.Post{}).Where("id = ?", *p.QuoteOfID).Update("quote_count", gorm.Expr("quote_count + 1")).Error; err != nil {
				tx.Rollback()
				return
			}
		}
	}

	if err := tx.Commit().Error; err != nil {
		return
	}
}

func moderateCommentV2(db *gorm.DB, cfg aiConfigProvider, id string) {
	var cmt model.Comment
	if err := db.First(&cmt, "id = ?", id).Error; err != nil {
		return
	}

	// Skip AI moderation for comments - auto-approve all
	LogAIModeration(db, "comment", id, cmt.UserID, 100, "approved", "auto_approve", "评论无需审核", map[string]any{
		"content_preview": cmt.Content,
		"post_id":         cmt.PostID,
	})

	wasHidden := cmt.Status != 0

	tx := db.Begin()
	if tx.Error != nil {
		return
	}

	if err := tx.Model(&model.Comment{}).Where("id = ?", id).Updates(map[string]any{"status": 0, "audit_status": 0, "audit_msg": nil}).Error; err != nil {
		tx.Rollback()
		return
	}

	// Only increment count if comment was previously hidden
	if wasHidden {
		if err := tx.Model(&model.Post{}).Where("id = ?", cmt.PostID).Update("comment_count", gorm.Expr("comment_count + 1")).Error; err != nil {
			tx.Rollback()
			return
		}
	}

	if err := tx.Commit().Error; err != nil {
		return
	}
}

func moderatePost(db *gorm.DB, cfg aiConfigProvider, id string) {
	var p model.Post
	if err := db.First(&p, "id = ?", id).Error; err != nil {
		return
	}
	// Build context
	cardType := "confession"
	if p.CardType != nil {
		trimmed := strings.TrimSpace(*p.CardType)
		if trimmed != "" {
			cardType = strings.ToLower(trimmed)
		}
	}
	ctxText := "CardType:" + cardType + "\n作者:" + p.AuthorName + "\n对象:" + p.TargetName + "\n内容:" + p.Content
	res, _ := ModerateWithRetry(context.Background(), NewConfigAdapter(cfg.GetAIBaseURL(), cfg.GetAIAPIKey(), cfg.GetAIModel()), BuildPostPrompt(ctxText, cardType))
	if res != nil && !res.Audit {
		msg := res.Msg
		_ = db.Model(&model.Post{}).Where("id = ?", id).Updates(map[string]any{
			"status": 1, "audit_status": 2, "audit_msg": msg,
		}).Error
		// Notify author (removed {{link}} placeholder, frontend will handle routing)
		Notify(db, p.AuthorID, "帖子审核未通过", "你的帖子未通过审核，原因："+msg+"。如有异议可申请人工复核。", map[string]any{"post_id": p.ID})
		return
	}
	// approved (or default approve on error)
	_ = db.Model(&model.Post{}).Where("id = ?", id).Updates(map[string]any{
		"status": 0, "audit_status": 0, "audit_msg": nil,
	}).Error
}

func moderateComment(db *gorm.DB, cfg aiConfigProvider, id string) {
	var cmt model.Comment
	if err := db.First(&cmt, "id = ?", id).Error; err != nil {
		return
	}
	res, _ := ModerateWithRetry(context.Background(), NewConfigAdapter(cfg.GetAIBaseURL(), cfg.GetAIAPIKey(), cfg.GetAIModel()), BuildCommentPrompt(cmt.Content))
	if res != nil && !res.Audit {
		msg := res.Msg
		_ = db.Model(&model.Comment{}).Where("id = ?", id).Updates(map[string]any{
			"status": 1, "audit_status": 2, "audit_msg": msg,
		}).Error
		// optional: notify comment author
		Notify(db, cmt.UserID, "评论审核未通过", "你的评论未通过审核，原因："+msg+"。", map[string]any{"comment_id": cmt.ID, "post_id": cmt.PostID})
		return
	}
	// approved: show comment and bump post comment_count
	tx := db.Begin()
	_ = tx.Model(&model.Comment{}).Where("id = ?", id).Updates(map[string]any{"status": 0, "audit_status": 0, "audit_msg": nil}).Error
	_ = tx.Model(&model.Post{}).Where("id = ?", cmt.PostID).Update("comment_count", gorm.Expr("comment_count + 1")).Error
	_ = tx.Commit().Error
}
