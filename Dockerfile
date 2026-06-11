# ============================================================
# Step CA Web Interface - Multi-stage Dockerfile
# ============================================================
# Usage:
#   # Build for current platform (default: linux/amd64)
#   docker build -t step-ca-web .
#
#   # Build for specific OS/arch
#   docker build --build-arg TARGETOS=linux --build-arg TARGETARCH=arm64 -t step-ca-web .
#
#   # Build for Windows
#   docker build --build-arg TARGETOS=windows --build-arg TARGETARCH=amd64 -t step-ca-web .
#
#   # Build for macOS (Apple Silicon)
#   docker build --build-arg TARGETOS=darwin --build-arg TARGETARCH=arm64 -t step-ca-web .
#
#   # Run
#   docker run -p 8080:8080 step-ca-web --ca-url https://your-ca:443
#
#   # Run with HTTPS
#   docker run -p 8443:8443 -v ./certs:/certs step-ca-web \
#     --ca-url https://your-ca:443 \
#     --https-listen :8443 \
#     --tls-cert /certs/tls.crt \
#     --tls-key /certs/tls.key
# ============================================================

# --- Build arguments ---
ARG TARGETOS=linux
ARG TARGETARCH=amd64

# ============================================================
# Stage 1: Build Vue frontend
# ============================================================
FROM node:20-alpine AS frontend-builder

WORKDIR /build/web

# Copy package files first for better layer caching
COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund

# Copy Vue source and build
COPY web/ ./
RUN npm run build

# ============================================================
# Stage 2: Build Go binary
# ============================================================
FROM golang:1.23-alpine AS go-builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go module files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy all Go source code
COPY . .

# Copy the built frontend assets into the embed directory
COPY --from=frontend-builder /build/web/dist ./web/dist/

# Build the Go binary for the target platform
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -X main.version=$(date +%Y%m%d)" \
    -o /out/step-ca-web${TARGETOS:+.exe} .

# Rename to consistent name for the next stage
RUN if [ "${TARGETOS}" = "windows" ]; then \
      cp /out/step-ca-web.exe /out/step-ca-web-bin; \
    else \
      cp /out/step-ca-web /out/step-ca-web-bin; \
    fi

# ============================================================
# Stage 3: Final minimal image
# ============================================================
FROM alpine:3.19

ARG TARGETOS=linux

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -h /app appuser

WORKDIR /app

# Copy binary from builder
COPY --from=go-builder /out/step-ca-web-bin ./step-ca-web

# Set ownership and permissions
RUN chown appuser:appuser /app/step-ca-web && \
    chmod +x /app/step-ca-web

USER appuser

# Expose default HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:8080/api/health || exit 1

ENTRYPOINT ["./step-ca-web"]
CMD ["--listen", ":8080"]
