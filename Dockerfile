# Build
FROM golang:1.24-alpine AS builder
WORKDIR /src
RUN apk add --no-cache build-base git
# Copy module descriptors first to leverage layer caching and ensure sums are present
COPY go.mod go.sum ./
RUN go mod download
# Copy the rest of the source
COPY . .
# Build the server
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /out/server ./cmd/server

# Runtime
FROM alpine:3.20
WORKDIR /app

# 固定 UID/GID，便于外部一致化
RUN addgroup -g 10001 app && adduser -D -H -u 10001 -G app app

# 用 su-exec（类似 gosu）来降权
RUN apk add --no-cache su-exec

COPY --from=builder /out/server /app/server

# 启动脚本：保证目录存在并修好属主后再降权运行
RUN printf '%s\n' \
  '#!/bin/sh' \
  'set -e' \
  'mkdir -p /app/data/uploads' \
  'chown -R app:app /app/data || true' \
  'exec su-exec app:app /app/server' > /usr/local/bin/entrypoint.sh \
  && chmod +x /usr/local/bin/entrypoint.sh

ENV PORT=8000
EXPOSE 8000
# 注意：保持 root 执行入口脚本（脚本里会降权）
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

