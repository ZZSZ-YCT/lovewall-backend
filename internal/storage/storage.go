package storage

import (
    "context"
    "io"
)

type Provider interface {
    Save(ctx context.Context, r io.Reader, filename string) (string, error)
}
