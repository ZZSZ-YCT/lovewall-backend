package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang/freetype/truetype"
	"github.com/google/uuid"
	"github.com/wenlng/go-captcha-assets/resources/fonts/fzshengsksjw"
	"github.com/wenlng/go-captcha-assets/resources/imagesv2"
	"github.com/wenlng/go-captcha-assets/resources/thumbs"
	"github.com/wenlng/go-captcha/v2/base/option"
	"github.com/wenlng/go-captcha/v2/click"
	"github.com/wenlng/go-captcha/v2/rotate"
	"go.uber.org/zap"

	"lovewall/internal/config"
)

const (
	captchaPadding    = 20
	cleanupInterval   = 5 * time.Second
	minCharsFallback  = 4
	minVerifyFallback = 2
	maxVerifyFallback = 4
	defaultStorageTTL = 60 * time.Second
	rotatePadding     = 10
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var (
	// ErrCaptchaRequired indicates missing captcha_id or payload.
	ErrCaptchaRequired = errors.New("captcha required")
	// ErrCaptchaInvalid indicates expired or unknown captcha_id.
	ErrCaptchaInvalid = errors.New("captcha invalid or expired")
	// ErrCaptchaFailed indicates the user-provided data is incorrect.
	ErrCaptchaFailed = errors.New("captcha validation failed")
	// ErrCaptchaTypeUnsupported indicates an unsupported captcha type.
	ErrCaptchaTypeUnsupported = errors.New("captcha type not supported")
)

// CaptchaType represents the configured captcha mode.
type CaptchaType string

const (
	CaptchaTypeClick  CaptchaType = "click"
	CaptchaTypeRotate CaptchaType = "rotate"
)

var defaultCaptchaChars = []string{
	"A", "B", "C", "D", "E", "F", "G", "H", "J", "K", "L", "M", "N", "P", "Q", "R", "S", "T",
	"U", "V", "W", "X", "Y", "Z",
	"2", "3", "4", "5", "6", "7", "8", "9",
}

// CaptchaResponse 生成验证码返回
type CaptchaResponse struct {
	CaptchaID   string `json:"captcha_id"`
	Type        string `json:"type"`
	MasterImage string `json:"master_image"`
	ThumbImage  string `json:"thumb_image"`
}

// DotInput 用户点击坐标
type DotInput struct {
	X int `json:"x"`
	Y int `json:"y"`
}

// VerifyPayload 描述验证码校验的动态参数
// Raw: 通用字段 (rotate/click 新协议)
// Dots: 兼容旧版 click 请求的坐标数组
type VerifyPayload struct {
	Raw  json.RawMessage
	Dots []DotInput
}

type captchaEntry struct {
	Type        CaptchaType
	clickDots   []*click.Dot
	rotateBlock *rotate.Block
	width       int
	height      int
	createdAt   time.Time
}

// CaptchaStorage 内存存储
type CaptchaStorage struct {
	data sync.Map
	ttl  time.Duration
}

// NewCaptchaStorage 创建内存存储
func NewCaptchaStorage(ttl time.Duration) *CaptchaStorage {
	if ttl <= 0 {
		ttl = defaultStorageTTL
	}
	s := &CaptchaStorage{ttl: ttl}
	go s.cleanupExpired()
	return s
}

func (s *CaptchaStorage) cleanupExpired() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		s.data.Range(func(key, value any) bool {
			entry, ok := value.(*captchaEntry)
			if !ok {
				s.data.Delete(key)
				return true
			}
			if now.Sub(entry.createdAt) > s.ttl {
				s.data.Delete(key)
			}
			return true
		})
	}
}

func (s *CaptchaStorage) Set(id string, entry *captchaEntry) {
	s.data.Store(id, entry)
}

func (s *CaptchaStorage) Get(id string) (*captchaEntry, bool) {
	if id == "" {
		return nil, false
	}
	value, ok := s.data.Load(id)
	if !ok {
		return nil, false
	}
	entry, ok := value.(*captchaEntry)
	if !ok {
		s.data.Delete(id)
		return nil, false
	}
	if time.Since(entry.createdAt) > s.ttl {
		s.data.Delete(id)
		return nil, false
	}
	return entry, true
}

func (s *CaptchaStorage) Delete(id string) {
	if id != "" {
		s.data.Delete(id)
	}
}

// CaptchaService 验证码服务
type CaptchaService struct {
	clickBuilder  *clickAdapter
	rotateBuilder *rotateAdapter
	storage       *CaptchaStorage
	cfg           *config.Config
}

func (s *CaptchaService) adapterForType(captchaType CaptchaType) (captchaAdapter, error) {
	switch captchaType {
	case CaptchaTypeClick:
		if s.clickBuilder != nil {
			return s.clickBuilder, nil
		}
	case CaptchaTypeRotate:
		if s.rotateBuilder != nil {
			return s.rotateBuilder, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrCaptchaTypeUnsupported, captchaType)
}

type captchaAdapter interface {
	Type() CaptchaType
	Generate() (*captchaResult, error)
	Verify(captchaID string, entry *captchaEntry, payload VerifyPayload) error
}

type captchaResult struct {
	entry       *captchaEntry
	masterImage string
	thumbImage  string
}

// NewCaptchaService 创建验证码服务
func NewCaptchaService(cfg *config.Config) (*CaptchaService, error) {
	if cfg == nil {
		return nil, errors.New("missing config")
	}
	if !cfg.CaptchaEnabled {
		return nil, errors.New("captcha is disabled by configuration")
	}

	backgrounds, err := imagesv2.GetImages()
	if err != nil {
		return nil, fmt.Errorf("load captcha backgrounds: %w", err)
	}
	if len(backgrounds) == 0 {
		return nil, errors.New("captcha backgrounds not found")
	}

	font, err := fzshengsksjw.GetFont()
	if err != nil {
		return nil, fmt.Errorf("load captcha fonts: %w", err)
	}

	thumbImages, err := thumbs.GetThumbs()
	if err != nil {
		zap.L().Warn("failed to load captcha thumb backgrounds, falling back to master backgrounds", zap.Error(err))
		thumbImages = nil
	}

	clickBuilder, err := newClickAdapter(cfg, []*truetype.Font{font}, backgrounds, thumbImages)
	if err != nil {
		return nil, err
	}

	rotateBuilder, err := newRotateAdapter(backgrounds)
	if err != nil {
		return nil, err
	}

	ttl := time.Duration(cfg.CaptchaTTLSeconds) * time.Second
	storage := NewCaptchaStorage(ttl)

	svc := &CaptchaService{
		clickBuilder:  clickBuilder,
		rotateBuilder: rotateBuilder,
		storage:       storage,
		cfg:           cfg,
	}

	if cfg.CaptchaType == "random" {
		zap.L().Info("Captcha service initialized",
			zap.String("mode", "random"),
			zap.String("types", "click/rotate"),
		)
	} else {
		zap.L().Info("Captcha service initialized", zap.String("type", cfg.CaptchaType))
	}

	return svc, nil
}

// Generate 生成新验证码
func (s *CaptchaService) Generate() (*CaptchaResponse, error) {
	var captchaType CaptchaType
	if s.cfg.CaptchaType == "random" {
		types := []CaptchaType{CaptchaTypeClick, CaptchaTypeRotate}
		captchaType = types[rand.Intn(len(types))]
	} else {
		captchaType = CaptchaType(s.cfg.CaptchaType)
	}

	builder, err := s.adapterForType(captchaType)
	if err != nil {
		return nil, err
	}

	result, err := builder.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate captcha: %w", err)
	}
	if result == nil || result.entry == nil {
		return nil, errors.New("captcha generation returned empty result")
	}

	captchaID := uuid.NewString()
	result.entry.createdAt = time.Now()
	s.storage.Set(captchaID, result.entry)

	return &CaptchaResponse{
		CaptchaID:   captchaID,
		Type:        string(captchaType),
		MasterImage: result.masterImage,
		ThumbImage:  result.thumbImage,
	}, nil
}

// Verify 验证验证码
func (s *CaptchaService) Verify(captchaID string, payload VerifyPayload) error {
	if strings.TrimSpace(captchaID) == "" {
		return ErrCaptchaRequired
	}

	entry, ok := s.storage.Get(captchaID)
	if !ok {
		return ErrCaptchaInvalid
	}

	// Delete immediately to ensure single-use even if verification fails.
	s.storage.Delete(captchaID)

	builder, err := s.adapterForType(entry.Type)
	if err != nil {
		return ErrCaptchaInvalid
	}

	if err := builder.Verify(captchaID, entry, payload); err != nil {
		return err
	}

	return nil
}

// -----------------------------------------------------------------------------
// Click adapter
// -----------------------------------------------------------------------------

type clickAdapter struct {
	builder click.Builder
}

func newClickAdapter(cfg *config.Config, fonts []*truetype.Font, backgrounds, thumbBackgrounds []image.Image) (*clickAdapter, error) {
	if len(fonts) == 0 {
		return nil, errors.New("captcha fonts not available")
	}
	if len(backgrounds) == 0 {
		return nil, errors.New("captcha backgrounds not available")
	}
	if len(thumbBackgrounds) == 0 {
		thumbBackgrounds = backgrounds
	}

	builder := click.NewBuilder()
	builder.SetResources(
		click.WithChars(defaultCaptchaChars),
		click.WithFonts(fonts),
		click.WithBackgrounds(backgrounds),
		click.WithThumbBackgrounds(thumbBackgrounds),
	)

	minChars, maxChars, minVerify, maxVerify := sanitizeClickRanges(cfg)
	builder.SetOptions(
		click.WithRangeLen(option.RangeVal{Min: minChars, Max: maxChars}),
		click.WithRangeVerifyLen(option.RangeVal{Min: minVerify, Max: maxVerify}),
	)

	return &clickAdapter{builder: builder}, nil
}

func (a *clickAdapter) Type() CaptchaType {
	return CaptchaTypeClick
}

func (a *clickAdapter) Generate() (*captchaResult, error) {
	captcha := a.builder.Make()
	data, err := captcha.Generate()
	if err != nil {
		return nil, err
	}

	masterB64, err := data.GetMasterImage().ToBase64Data()
	if err != nil {
		return nil, fmt.Errorf("encode master image: %w", err)
	}
	thumbB64, err := data.GetThumbImage().ToBase64Data()
	if err != nil {
		return nil, fmt.Errorf("encode thumb image: %w", err)
	}

	dots := make([]*click.Dot, 0, len(data.GetData()))
	for _, dot := range data.GetData() {
		dots = append(dots, dot)
	}
	sort.Slice(dots, func(i, j int) bool {
		return dots[i].Index < dots[j].Index
	})

	size := captcha.GetOptions().GetImageSize()
	entry := &captchaEntry{
		Type:      CaptchaTypeClick,
		clickDots: dots,
		width:     size.Width,
		height:    size.Height,
	}

	return &captchaResult{entry: entry, masterImage: masterB64, thumbImage: thumbB64}, nil
}

func (a *clickAdapter) Verify(captchaID string, entry *captchaEntry, payload VerifyPayload) error {
	dots, err := parseClickDots(payload.Raw, payload.Dots)
	if err != nil {
		return err
	}

	if len(dots) != len(entry.clickDots) {
		zap.L().Warn("captcha dots mismatch",
			zap.String("captcha_id", captchaID),
			zap.Int("expected", len(entry.clickDots)),
			zap.Int("received", len(dots)),
		)
		return ErrCaptchaFailed
	}

	for idx, input := range dots {
		target := entry.clickDots[idx]
		width := dimensionOrFallback(target.Width, target.Size)
		height := dimensionOrFallback(target.Height, target.Size)
		if !click.Validate(input.X, input.Y, target.X, target.Y, width, height, captchaPadding) {
			zap.L().Warn("captcha coordinate mismatch",
				zap.String("captcha_id", captchaID),
				zap.Int("target_index", target.Index),
				zap.Int("user_x", input.X),
				zap.Int("user_y", input.Y),
			)
			return ErrCaptchaFailed
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Rotate adapter
// -----------------------------------------------------------------------------

type rotateAdapter struct {
	builder rotate.Builder
}

func newRotateAdapter(images []image.Image) (*rotateAdapter, error) {
	if len(images) == 0 {
		return nil, errors.New("rotate images not available")
	}
	builder := rotate.NewBuilder()
	builder.SetResources(
		rotate.WithImages(images),
	)
	return &rotateAdapter{builder: builder}, nil
}

func (a *rotateAdapter) Type() CaptchaType {
	return CaptchaTypeRotate
}

func (a *rotateAdapter) Generate() (*captchaResult, error) {
	captcha := a.builder.Make()
	data, err := captcha.Generate()
	if err != nil {
		return nil, err
	}

	block := data.GetData()
	if block == nil {
		return nil, errors.New("rotate captcha block missing")
	}

	masterB64, err := data.GetMasterImage().ToBase64Data()
	if err != nil {
		return nil, fmt.Errorf("encode master image: %w", err)
	}
	thumbB64, err := data.GetThumbImage().ToBase64Data()
	if err != nil {
		return nil, fmt.Errorf("encode thumb image: %w", err)
	}

	entry := &captchaEntry{
		Type:        CaptchaTypeRotate,
		rotateBlock: cloneRotateBlock(block),
	}

	return &captchaResult{entry: entry, masterImage: masterB64, thumbImage: thumbB64}, nil
}

func (a *rotateAdapter) Verify(captchaID string, entry *captchaEntry, payload VerifyPayload) error {
	if entry.rotateBlock == nil {
		return ErrCaptchaInvalid
	}

	input, err := parseRotateInput(payload.Raw)
	if err != nil {
		return err
	}

	if !rotate.Validate(entry.rotateBlock.Angle, input.Angle, rotatePadding) {
		zap.L().Warn("rotate captcha mismatch",
			zap.String("captcha_id", captchaID),
			zap.Int("expected_angle", entry.rotateBlock.Angle),
			zap.Int("user_angle", input.Angle),
		)
		return ErrCaptchaFailed
	}

	return nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func sanitizeClickRanges(cfg *config.Config) (minChars, maxChars, minVerify, maxVerify int) {
	minChars = cfg.CaptchaMinChars
	if minChars <= 0 {
		minChars = minCharsFallback
	}
	maxChars = cfg.CaptchaMaxChars
	if maxChars < minChars {
		maxChars = minChars
	}

	maxVerifyAllowed := minChars
	minVerify = cfg.CaptchaMinVerify
	if minVerify <= 0 {
		minVerify = minVerifyFallback
	}
	if minVerify > maxVerifyAllowed {
		minVerify = maxVerifyAllowed
	}

	maxVerify = cfg.CaptchaMaxVerify
	if maxVerify <= 0 {
		maxVerify = maxVerifyFallback
	}
	if maxVerify > maxVerifyAllowed {
		maxVerify = maxVerifyAllowed
	}
	if maxVerify < minVerify {
		maxVerify = minVerify
	}

	return
}

func dimensionOrFallback(val, fallback int) int {
	if val > 0 {
		return val
	}
	if fallback > 0 {
		return fallback
	}
	return 24
}

func parseClickDots(raw json.RawMessage, legacyDots []DotInput) ([]DotInput, error) {
	var objErr, arrErr error

	if len(raw) > 0 {
		var objFormat struct {
			Dots []DotInput `json:"dots"`
		}
		if objErr = json.Unmarshal(raw, &objFormat); objErr == nil && len(objFormat.Dots) > 0 {
			return objFormat.Dots, nil
		}

		var arrFormat []DotInput
		if arrErr = json.Unmarshal(raw, &arrFormat); arrErr == nil && len(arrFormat) > 0 {
			return arrFormat, nil
		}

		if objErr != nil && arrErr != nil {
			zap.L().Warn("failed to decode click captcha payload", zap.Error(arrErr))
			return nil, ErrCaptchaFailed
		}
	}

	if len(legacyDots) > 0 {
		return legacyDots, nil
	}

	return nil, ErrCaptchaRequired
}

func parseRotateInput(raw json.RawMessage) (*rotateInput, error) {
	if len(raw) == 0 {
		return nil, ErrCaptchaRequired
	}
	var input rotateInput
	if err := json.Unmarshal(raw, &input); err != nil {
		zap.L().Warn("failed to decode rotate captcha payload", zap.Error(err))
		return nil, ErrCaptchaFailed
	}
	return &input, nil
}

type rotateInput struct {
	Angle int `json:"angle"`
}

func cloneRotateBlock(b *rotate.Block) *rotate.Block {
	if b == nil {
		return nil
	}
	clone := *b
	return &clone
}
