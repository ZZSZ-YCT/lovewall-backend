package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	basichttp "lovewall/internal/http"
	"lovewall/internal/service"
)

type CaptchaHandler struct {
	svc *service.CaptchaService
}

func NewCaptchaHandler(svc *service.CaptchaService) *CaptchaHandler {
	return &CaptchaHandler{svc: svc}
}

func (h *CaptchaHandler) Generate(c *gin.Context) {
	if h.svc == nil {
		zap.L().Error("captcha service unavailable")
		basichttp.Fail(c, http.StatusInternalServerError, "CAPTCHA_GENERATE_FAILED", "验证码生成失败")
		return
	}

	resp, err := h.svc.Generate()
	if err != nil {
		zap.L().Error("failed to generate captcha", zap.Error(err))
		basichttp.Fail(c, http.StatusInternalServerError, "CAPTCHA_GENERATE_FAILED", "验证码生成失败")
		return
	}

	basichttp.OK(c, resp)
}
