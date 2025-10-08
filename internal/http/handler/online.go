package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lovewall/internal/config"
	basichttp "lovewall/internal/http"
	"lovewall/internal/model"
)

type OnlineHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewOnlineHandler(db *gorm.DB, cfg *config.Config) *OnlineHandler {
	return &OnlineHandler{db: db, cfg: cfg}
}

// GET /api/users/:id/online (public) — 查询任意用户的在线状态
func (h *OnlineHandler) GetUserOnlineStatus(c *gin.Context) {
	userID := c.Param("id")

	var u model.User
	if err := h.db.Select("is_online, last_heartbeat").First(&u, "id = ? AND deleted_at IS NULL", userID).Error; err != nil {
		basichttp.Fail(c, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	basichttp.OK(c, gin.H{
		"user_id":        userID,
		"online":         u.IsOnline,
		"last_heartbeat": u.LastHeartbeat,
	})
}
