package service

import (
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"lovewall/internal/model"
)

// StartHeartbeatMonitor 启动心跳超时检测任务
// 每1分钟检查一次,5分钟无心跳标记为离线
func StartHeartbeatMonitor(db *gorm.DB) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			// 计算超时阈值: 当前时间减去5分钟
			timeout := time.Now().Add(-5 * time.Minute)
			// 将所有在线但心跳超时的用户标记为离线
			if err := db.Model(&model.User{}).
				Where("is_online = ? AND (last_heartbeat IS NULL OR last_heartbeat < ?)", true, timeout).
				Update("is_online", false).Error; err != nil {
				zap.L().Error("heartbeat monitor failed to update offline users", zap.Error(err))
			}
		}
	}()
}
