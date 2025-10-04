package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type LocalProvider struct {
	BaseDir string
}

func (lp *LocalProvider) Save(ctx context.Context, r io.Reader, filename string) (string, error) {
	if err := os.MkdirAll(lp.BaseDir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(lp.BaseDir, filename)
	// Ensure subdirectories exist when filename contains nested paths (e.g., avatars/userid-xxx.jpg)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, r); err != nil {
		return "", err
	}
	return dst, nil
}

func SafeName(name string) string {
	return filepath.Base(name)
}

func ExtFromMIME(mime string) string {
	switch mime {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	case "image/gif":
		return ".gif"
	default:
		return ""
	}
}

func JoinURL(base, name string) string {
	if base == "" {
		return name
	}
	if base == "/" {
		return fmt.Sprintf("/%s", name)
	}
	if base[len(base)-1] == '/' {
		return base + name
	}
	return base + "/" + name
}
