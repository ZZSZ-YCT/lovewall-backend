package model

import (
    "time"
)

type BaseModel struct {
    ID        string     `gorm:"primaryKey;type:text" json:"id"`
    CreatedAt time.Time  `json:"created_at"`
    UpdatedAt time.Time  `json:"updated_at"`
    DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty"`
}

type User struct {
    BaseModel
    Username      string  `gorm:"uniqueIndex;not null" json:"username"`
    DisplayName   *string `json:"display_name"`
    Email         *string `gorm:"uniqueIndex" json:"email,omitempty"`
    Phone         *string `gorm:"uniqueIndex" json:"phone,omitempty"`
    AvatarURL     *string `json:"avatar_url,omitempty"`
    Bio           *string `json:"bio,omitempty"`
    PasswordHash  string  `json:"-"`
    IsSuperadmin  bool    `gorm:"not null;default:false" json:"is_superadmin"`
    Status        int     `gorm:"not null;default:0" json:"status"`
    LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
    LastIP        *string    `json:"last_ip,omitempty"`
    Metadata      *string    `json:"metadata,omitempty"`
}

type ExternalIdentity struct {
    BaseModel
    UserID      string  `gorm:"index;not null" json:"user_id"`
    Provider    string  `gorm:"index:uniq_prov_sub,unique;not null" json:"provider"`
    Subject     string  `gorm:"index:uniq_prov_sub,unique;not null" json:"subject"`
    Email       *string `json:"email,omitempty"`
    Username    *string `json:"username,omitempty"`
    AvatarURL   *string `json:"avatar_url,omitempty"`
    AccessToken *string `json:"-"`
    RefreshToken *string `json:"-"`
    ExpiresAt   *time.Time `json:"expires_at,omitempty"`
    Metadata    *string    `json:"metadata,omitempty"`
}

type Post struct {
    BaseModel
    AuthorID    string  `gorm:"index;not null" json:"author_id"`
    AuthorName  string  `gorm:"not null" json:"author_name"`
    TargetName  string  `gorm:"not null" json:"target_name"`
    Content     string  `gorm:"not null" json:"content"`
    ImagePath   *string `json:"image_path,omitempty"`
    Status      int     `gorm:"not null;default:0;index" json:"status"`
    IsPinned    bool    `gorm:"not null;default:false;index" json:"is_pinned"`
    IsFeatured  bool    `gorm:"not null;default:false;index" json:"is_featured"`
    Metadata    *string `json:"metadata,omitempty"`
}

type Comment struct {
    BaseModel
    PostID   string  `gorm:"index;not null" json:"post_id"`
    UserID   string  `gorm:"index;not null" json:"user_id"`
    Content  string  `gorm:"not null" json:"content"`
    Status   int     `gorm:"not null;default:0;index" json:"status"`
    Metadata *string `json:"metadata,omitempty"`
}

type Announcement struct {
    BaseModel
    Title     string  `gorm:"not null" json:"title"`
    Content   string  `gorm:"not null" json:"content"`
    IsActive  bool    `gorm:"not null;default:true;index" json:"is_active"`
    Metadata  *string `json:"metadata,omitempty"`
}

type UserPermission struct {
    BaseModel
    UserID     string `gorm:"index:uniq_user_perm,unique;not null" json:"user_id"`
    Permission string `gorm:"index:uniq_user_perm,unique;not null" json:"permission"`
}

