# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

ARG VERSION=dev
WORKDIR /src

# Pure stdlib — no go.sum needed, just copy sources and build
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} -s -w" \
    -o /satpam-server .

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache wget tzdata ca-certificates && \
    addgroup -S satpam && adduser -S -G satpam satpam

COPY --from=builder /satpam-server /usr/local/bin/satpam-server

# /rules is mounted as a volume at runtime
RUN mkdir -p /rules && chown satpam:satpam /rules

USER satpam
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["satpam-server"]
CMD ["--rules", "/rules"]
