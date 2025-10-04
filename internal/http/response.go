package http

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type SuccessResp struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	TraceID string      `json:"trace_id"`
}

type ErrorResp struct {
	Success bool      `json:"success"`
	Error   ErrorBody `json:"error"`
	TraceID string    `json:"trace_id"`
}

func traceID(c *gin.Context) string {
	if id := c.Writer.Header().Get("X-Trace-ID"); id != "" {
		return id
	}
	id := uuid.NewString()
	c.Writer.Header().Set("X-Trace-ID", id)
	return id
}

func OK(c *gin.Context, data interface{}) {
	c.JSON(200, SuccessResp{Success: true, Data: data, TraceID: traceID(c)})
}

func JSON(c *gin.Context, code int, data interface{}) {
	c.JSON(code, SuccessResp{Success: true, Data: data, TraceID: traceID(c)})
}

func Fail(c *gin.Context, httpCode int, code, msg string) {
	c.JSON(httpCode, ErrorResp{Success: false, Error: ErrorBody{Code: code, Message: msg}, TraceID: traceID(c)})
}

// FailWithExtras allows attaching extra top-level fields to error responses
// while preserving the unified envelope.
func FailWithExtras(c *gin.Context, httpCode int, code, msg string, extras gin.H) {
	tid := traceID(c)
	payload := gin.H{
		"success":  false,
		"error":    gin.H{"code": code, "message": msg},
		"trace_id": tid,
	}
	for k, v := range extras {
		payload[k] = v
	}
	c.JSON(httpCode, payload)
}
