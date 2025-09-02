# Build
FROM golang:1.22-alpine AS builder
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
RUN adduser -D -H app && mkdir -p /app/data/uploads && chown -R app:app /app
COPY --from=builder /out/server /app/server
USER app
ENV PORT=8000
EXPOSE 8000
ENTRYPOINT ["/app/server"]
