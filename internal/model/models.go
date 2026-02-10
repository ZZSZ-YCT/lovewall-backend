package model

import (
	"time"

	"gorm.io/gorm"
	"lovewall/internal/utils"
)

type BaseModel struct {
	ID        string     `gorm:"primaryKey;type:text" json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty"`
}

// BeforeCreate hook to generate UUID for all models with duplicate checking
func (base *BaseModel) BeforeCreate(tx *gorm.DB) error {
	if base.ID == "" {
		// Get table name from the statement
		tableName := tx.Statement.Table
		if tableName == "" {
			// Fallback to schema table name
			tableName = tx.Statement.Schema.Table
		}

		// Generate unique ID with database verification
		uniqueID, err := utils.GenerateUniqueID(tx, tableName, "id")
		if err != nil {
			return err
		}
		base.ID = uniqueID
	} else {
		// Validate provided ID
		normalized, err := utils.NormalizeUUID(base.ID)
		if err != nil {
			return err
		}
		base.ID = normalized
	}
	return nil
}

type User struct {
	BaseModel
	Username       string     `gorm:"uniqueIndex;not null" json:"username"`
	DisplayName    *string    `json:"display_name"`
	Email          *string    `gorm:"uniqueIndex" json:"email,omitempty"`
	Phone          *string    `gorm:"uniqueIndex" json:"phone,omitempty"`
	AvatarURL      *string    `json:"avatar_url,omitempty"`
	BannerURL      *string    `json:"banner_url,omitempty"`
	Bio            *string    `json:"bio,omitempty"`
	PasswordHash   string     `json:"-"`
	IsSuperadmin   bool       `gorm:"not null;default:false" json:"is_superadmin"`
	Status         int        `gorm:"not null;default:0" json:"status"`
	IsBanned       bool       `gorm:"not null;default:false;index" json:"is_banned"`
	BanReason      *string    `json:"ban_reason,omitempty"`
	BannedAt       *time.Time `json:"banned_at,omitempty"`
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
	IsOnline       bool       `gorm:"not null;default:false;index" json:"is_online"`
	LastHeartbeat  *time.Time `json:"last_heartbeat,omitempty"`
	LastIP         *string    `json:"last_ip,omitempty"`
	Metadata       *string    `json:"metadata,omitempty"`
	FollowerCount  int        `gorm:"not null;default:0" json:"follower_count"`
	FollowingCount int        `gorm:"not null;default:0" json:"following_count"`
}

type ExternalIdentity struct {
	BaseModel
	UserID       string     `gorm:"index;not null" json:"user_id"`
	Provider     string     `gorm:"index:uniq_prov_sub,unique;not null" json:"provider"`
	Subject      string     `gorm:"index:uniq_prov_sub,unique;not null" json:"subject"`
	Email        *string    `json:"email,omitempty"`
	Username     *string    `json:"username,omitempty"`
	AvatarURL    *string    `json:"avatar_url,omitempty"`
	AccessToken  *string    `json:"-"`
	RefreshToken *string    `json:"-"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Metadata     *string    `json:"metadata,omitempty"`
}

type Post struct {
	BaseModel
	AuthorID   string  `gorm:"index;not null" json:"author_id"`
	AuthorName string  `gorm:"not null" json:"author_name"`
	TargetName string  `gorm:"not null" json:"target_name"`
	Content    string  `gorm:"not null" json:"content"`
	ImagePath  *string `json:"image_path,omitempty"`
	Status     int     `gorm:"not null;default:0;index" json:"status"`
	IsPinned   bool    `gorm:"not null;default:false;index" json:"is_pinned"`
	IsFeatured bool    `gorm:"not null;default:false;index" json:"is_featured"`
	IsLocked   bool    `gorm:"not null;default:false" json:"is_locked"`
	// confessor_mode: "self" uses current user's display name; "custom" uses stored AuthorName
	ConfessorMode *string `gorm:"not null;default:custom" json:"confessor_mode"`
	CardType      *string `gorm:"not null;default:confession;index" json:"card_type"`
	Metadata      *string `json:"metadata,omitempty"`

	// X-style fields: reply, repost, quote
	ReplyToID  *string `gorm:"index" json:"reply_to_id"`
	RepostOfID *string `gorm:"index" json:"repost_of_id"`
	QuoteOfID  *string `gorm:"index" json:"quote_of_id"`

	// Stats
	ViewCount    int `gorm:"not null;default:0" json:"view_count"`
	CommentCount int `gorm:"not null;default:0" json:"comment_count"`
	LikeCount    int `gorm:"not null;default:0" json:"like_count"`
	RepostCount  int `gorm:"not null;default:0" json:"repost_count"`
	QuoteCount   int `gorm:"not null;default:0" json:"quote_count"`
	ReplyCount   int `gorm:"not null;default:0" json:"reply_count"`

	// Moderation
	AuditStatus           int     `gorm:"not null;default:0" json:"audit_status"` // 0=approved,1=pending,2=rejected
	AuditMsg              *string `json:"audit_msg,omitempty"`
	ManualReviewRequested bool    `gorm:"not null;default:false" json:"manual_review_requested"`
}

// PostImage stores multiple image URLs for a post
type PostImage struct {
	BaseModel
	PostID    string `gorm:"index;not null" json:"post_id"`
	URL       string `gorm:"not null" json:"url"`
	SortOrder int    `gorm:"not null;default:0;index" json:"sort_order"`
}

// PostLike records a user liking a post
type PostLike struct {
	BaseModel
	UserID string `gorm:"index:uniq_user_post_like,unique;not null" json:"user_id"`
	PostID string `gorm:"index:uniq_user_post_like,unique;not null" json:"post_id"`
}

// PostMention records @mentions in a post
type PostMention struct {
	BaseModel
	PostID          string `gorm:"index;not null" json:"post_id"`
	MentionedUserID string `gorm:"index;not null" json:"mentioned_user_id"`
	Username        string `gorm:"not null" json:"username"`
}

// UserFollow records follow relationships (follower_id follows following_id)
type UserFollow struct {
	BaseModel
	FollowerID  string `gorm:"index:uniq_follower_following,unique;not null" json:"follower_id"`
	FollowingID string `gorm:"index:uniq_follower_following,unique;not null" json:"following_id"`
}

// UserBlock records block relationships (blocker_id blocks blocked_id)
type UserBlock struct {
	BaseModel
	BlockerID string `gorm:"index:uniq_blocker_blocked,unique;not null" json:"blocker_id"`
	BlockedID string `gorm:"index:uniq_blocker_blocked,unique;not null" json:"blocked_id"`
}

type Comment struct {
	BaseModel
	PostID   string  `gorm:"index;not null" json:"post_id"`
	UserID   string  `gorm:"index;not null" json:"user_id"`
	Content  string  `gorm:"not null" json:"content"`
	Status   int     `gorm:"not null;default:0;index" json:"status"`
	IsPinned bool    `gorm:"not null;default:false" json:"is_pinned"`
	Metadata *string `json:"metadata,omitempty"`
	// Moderation
	AuditStatus int     `gorm:"not null;default:0" json:"audit_status"` // 0=approved,1=pending,2=rejected
	AuditMsg    *string `json:"audit_msg,omitempty"`
}

type Announcement struct {
	BaseModel
	Path     string  `gorm:"not null;uniqueIndex" json:"path"`
	Content  string  `gorm:"not null" json:"content"`
	IsActive bool    `gorm:"not null;default:true;index" json:"is_active"`
	Metadata *string `json:"metadata,omitempty"`
}

type UserPermission struct {
	BaseModel
	UserID     string `gorm:"index:uniq_user_perm,unique;not null" json:"user_id"`
	Permission string `gorm:"index:uniq_user_perm,unique;not null" json:"permission"`
}

type Tag struct {
	BaseModel
	Name            string  `gorm:"not null;uniqueIndex" json:"name"`
	Title           string  `gorm:"not null" json:"title"`
	BackgroundColor string  `gorm:"not null" json:"background_color"`
	TextColor       string  `gorm:"not null" json:"text_color"`
	Description     *string `json:"description,omitempty"`
	IsActive        bool    `gorm:"not null;default:true;index" json:"is_active"`
	TagType         string  `gorm:"type:varchar(20);not null;default:'collective';index" json:"tag_type"`
	CssStyles       *string `gorm:"type:text" json:"css_styles,omitempty"`
	Metadata        *string `json:"metadata,omitempty"`
}

type RedemptionCode struct {
	BaseModel
	Code      string     `gorm:"not null;uniqueIndex" json:"code"`
	TagID     string     `gorm:"index;not null" json:"tag_id"`
	IsUsed    bool       `gorm:"not null;default:false;index" json:"is_used"`
	UsedBy    *string    `gorm:"index" json:"used_by,omitempty"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	ExpiresAt *time.Time `gorm:"index" json:"expires_at,omitempty"`
	BatchID   *string    `gorm:"index" json:"batch_id,omitempty"`
	Metadata  *string    `json:"metadata,omitempty"`

	// Relations
	Tag  Tag   `gorm:"foreignKey:TagID;references:ID" json:"tag,omitempty"`
	User *User `gorm:"foreignKey:UsedBy;references:ID" json:"user,omitempty"`
}

type UserTag struct {
	BaseModel
	UserID     string    `gorm:"index:uniq_user_tag,unique;not null" json:"user_id"`
	TagID      string    `gorm:"index:uniq_user_tag,unique;not null" json:"tag_id"`
	ObtainedAt time.Time `gorm:"not null;default:current_timestamp" json:"obtained_at"`
	IsActive   bool      `gorm:"not null;default:false;index" json:"is_active"`

	// Relations
	User User `gorm:"foreignKey:UserID;references:ID" json:"user,omitempty"`
	Tag  Tag  `gorm:"foreignKey:TagID;references:ID" json:"tag,omitempty"`
}

// Logging models

// RequestLog stores per-request basic information. No public API exposure.
type RequestLog struct {
	BaseModel
	UserID     *string `gorm:"index" json:"user_id,omitempty"`
	Method     string  `gorm:"not null" json:"method"`
	Path       string  `gorm:"not null;index" json:"path"`
	Query      *string `json:"query,omitempty"`
	Status     int     `gorm:"not null" json:"status"`
	IP         *string `json:"ip,omitempty"`
	UserAgent  *string `json:"user_agent,omitempty"`
	DurationMs int64   `gorm:"not null" json:"duration_ms"`
	TraceID    *string `json:"trace_id,omitempty"`
}

// SubmissionLog records user submissions such as creating posts or comments.
type SubmissionLog struct {
	BaseModel
	UserID     string  `gorm:"index;not null" json:"user_id"`
	Action     string  `gorm:"not null;index" json:"action"`      // e.g., post_create, comment_create
	ObjectType string  `gorm:"not null;index" json:"object_type"` // e.g., post, comment
	ObjectID   string  `gorm:"not null;index" json:"object_id"`
	Metadata   *string `json:"metadata,omitempty"`
}

// OperationLog records administrator operations and AI moderation actions.
// For AI operations, AdminID is set to AI_SYSTEM_UUID constant.
type OperationLog struct {
	BaseModel
	AdminID    string  `gorm:"index;not null" json:"admin_id"` // User ID or AI_SYSTEM_UUID
	Action     string  `gorm:"not null;index" json:"action"`   // e.g., pin_post, ai_auto_approve, ai_auto_delete
	ObjectType string  `gorm:"not null;index" json:"object_type"`
	ObjectID   string  `gorm:"not null;index" json:"object_id"`
	Metadata   *string `json:"metadata,omitempty"`
}

// AI_SYSTEM_UUID is a fixed UUID representing AI moderation system operations
const AI_SYSTEM_UUID = "00000000-0000-0000-0000-000000000001"

// PostView records unique user views for posts (one per user per post)
type PostView struct {
	BaseModel
	UserID string `gorm:"index:uniq_user_post,unique;not null" json:"user_id"`
	PostID string `gorm:"index:uniq_user_post,unique;not null" json:"post_id"`
}

// Notification: system -> user messages (pull-based)
type Notification struct {
	BaseModel
	UserID   string  `gorm:"index;not null" json:"user_id"`
	Title    string  `gorm:"not null" json:"title"`
	Content  string  `gorm:"not null" json:"content"`
	IsRead   bool    `gorm:"not null;default:false;index" json:"is_read"`
	Metadata *string `json:"metadata,omitempty"`
}

// UserSession stores active login sessions per user.
// Tokens include a JTI which is recorded here and validated on each request.
// Deleting rows immediately invalidates the corresponding tokens.
type UserSession struct {
	BaseModel
	UserID    string    `gorm:"index;not null" json:"user_id"`
	JTI       string    `gorm:"uniqueIndex;not null" json:"jti"`
	ExpiresAt time.Time `gorm:"index;not null" json:"expires_at"`
	IP        *string   `json:"ip,omitempty"`
	UserAgent *string   `json:"user_agent,omitempty"`
}
