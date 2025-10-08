package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// GeetestValidator handles Geetest CAPTCHA verification
type GeetestValidator struct {
	captchaID  string
	captchaKey string
	apiURL     string
	httpClient *http.Client
}

// NewGeetestValidator creates a new Geetest validator instance
func NewGeetestValidator(captchaID, captchaKey string) *GeetestValidator {
	return &GeetestValidator{
		captchaID:  captchaID,
		captchaKey: captchaKey,
		apiURL:     "http://gcaptcha4.geetest.com/validate",
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// GeetestValidateRequest represents the validation data from frontend
type GeetestValidateRequest struct {
	LotNumber     string `json:"lot_number" binding:"required"`
	CaptchaOutput string `json:"captcha_output" binding:"required"`
	PassToken     string `json:"pass_token" binding:"required"`
	GenTime       string `json:"gen_time" binding:"required"`
}

// GeetestValidateResponse represents the response from Geetest API
type GeetestValidateResponse struct {
	Result string                 `json:"result"`
	Reason string                 `json:"reason"`
	Args   map[string]interface{} `json:"captcha_args,omitempty"`
}

// generateSignToken generates HMAC-SHA256 signature for validation
func (g *GeetestValidator) generateSignToken(lotNumber string) string {
	h := hmac.New(sha256.New, []byte(g.captchaKey))
	h.Write([]byte(lotNumber))
	return hex.EncodeToString(h.Sum(nil))
}

// Validate performs server-side validation of Geetest CAPTCHA
func (g *GeetestValidator) Validate(req *GeetestValidateRequest) (bool, error) {
	// Validate configuration
	if g.captchaID == "" || g.captchaKey == "" {
		return false, errors.New("geetest not configured: missing GEETEST_CAPTCHA_ID or GEETEST_CAPTCHA_KEY")
	}

	// Generate signature
	signToken := g.generateSignToken(req.LotNumber)

	// Prepare request parameters
	params := url.Values{}
	params.Set("lot_number", req.LotNumber)
	params.Set("captcha_output", req.CaptchaOutput)
	params.Set("pass_token", req.PassToken)
	params.Set("gen_time", req.GenTime)
	params.Set("captcha_id", g.captchaID)
	params.Set("sign_token", signToken)

	// Make HTTP request to Geetest API
	resp, err := g.httpClient.PostForm(g.apiURL, params)
	if err != nil {
		return false, fmt.Errorf("geetest api request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read geetest response: %w", err)
	}

	// Parse response
	var apiResp GeetestValidateResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return false, fmt.Errorf("failed to parse geetest response: %w", err)
	}

	// Check validation result
	if apiResp.Result != "success" {
		return false, fmt.Errorf("geetest validation failed: %s", apiResp.Reason)
	}

	return true, nil
}

// IsEnabled checks if Geetest validation is enabled
func (g *GeetestValidator) IsEnabled() bool {
	return g.captchaID != "" && g.captchaKey != ""
}
