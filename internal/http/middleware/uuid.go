package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"lovewall/internal/utils"
	basichttp "lovewall/internal/http"
)

// ValidateUUIDParam validates UUID in path parameters
func ValidateUUIDParam(paramName string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		paramValue := c.Param(paramName)
		if paramValue == "" {
			basichttp.Fail(c, http.StatusBadRequest, "VALIDATION_FAILED", "missing "+paramName)
			c.Abort()
			return
		}

		if !utils.IsValidUUID(paramValue) {
			basichttp.Fail(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid "+paramName+" format")
			c.Abort()
			return
		}

		// Store normalized UUID in context for use by handlers
		normalized, err := utils.NormalizeUUID(paramValue)
		if err != nil {
			basichttp.Fail(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid "+paramName+" format")
			c.Abort()
			return
		}

		// Replace the param with normalized version
		c.Params = append(c.Params[:0], gin.Param{Key: paramName, Value: normalized})
		
		c.Next()
	})
}

// ValidateUUIDParams validates multiple UUID parameters
func ValidateUUIDParams(paramNames ...string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		normalizedParams := make([]gin.Param, 0, len(c.Params))
		
		for _, param := range c.Params {
			isUUIDParam := false
			for _, name := range paramNames {
				if param.Key == name {
					isUUIDParam = true
					break
				}
			}
			
			if isUUIDParam {
				if !utils.IsValidUUID(param.Value) {
					basichttp.Fail(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid "+param.Key+" format")
					c.Abort()
					return
				}
				
				normalized, err := utils.NormalizeUUID(param.Value)
				if err != nil {
					basichttp.Fail(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid "+param.Key+" format")
					c.Abort()
					return
				}
				
				normalizedParams = append(normalizedParams, gin.Param{Key: param.Key, Value: normalized})
			} else {
				normalizedParams = append(normalizedParams, param)
			}
		}
		
		c.Params = normalizedParams
		c.Next()
	})
}