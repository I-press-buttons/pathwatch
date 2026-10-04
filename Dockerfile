# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage
#
# Runs on the *build* platform (e.g. the amd64 CI runner) and cross-compiles
# the pure-Go binary for the *target* platform. No QEMU is needed for the Go
# compile, which keeps multi-arch builds fast.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

ARG TARGETOS
ARG TARGETARCH
# Version string injected into the binary (main.version). The CI passes a tag,
# `git describe` output or `edge-<sha>`.
ARG VERSION=dev

WORKDIR /src

# Download modules first so this layer is cached until go.mod/go.sum change.
# (go.sum* so the build does not fail while a project has no dependencies.)
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/pathwatch ./cmd/pathwatch

# ---------------------------------------------------------------------------
# Runtime stage
#
# Small Alpine with CA certificates (HTTPS probes, webhooks) and tzdata (TZ
# support). A shell is kept on purpose: handy for debugging on a Synology via
# `docker exec -it pathwatch sh`.
#
# The container runs as root. That is deliberate: raw ICMP sockets work
# reliably as root + NET_RAW on Synology kernels, where unprivileged ICMP
# ("ping group") sockets are often not enabled.
# ---------------------------------------------------------------------------
FROM alpine:3.22

ARG VERSION=dev

RUN apk add --no-cache ca-certificates tzdata

COPY --from=build /out/pathwatch /usr/local/bin/pathwatch
COPY deploy/healthcheck.sh /usr/local/bin/pathwatch-healthcheck
RUN chmod 0755 /usr/local/bin/pathwatch-healthcheck

LABEL org.opencontainers.image.title="pathwatch" \
      org.opencontainers.image.description="Self-hosted network path analysis and monitoring tool: per-hop latency and loss timelines correlated with HTTP phase timing." \
      org.opencontainers.image.source="https://github.com/i-press-buttons/pathwatch" \
      org.opencontainers.image.url="https://github.com/i-press-buttons/pathwatch" \
      org.opencontainers.image.documentation="https://github.com/i-press-buttons/pathwatch/blob/main/docs/SYNOLOGY.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# Everything stateful lives in one volume: /data/pathwatch.yaml,
# /data/pathwatch.db and /data/.pathwatch-password. A starter config is
# created on first run.
ENV PATHWATCH_CONFIG=/data/pathwatch.yaml \
    PATHWATCH_DB=/data/pathwatch.db \
    PATHWATCH_LISTEN=0.0.0.0:8095 \
    TZ=UTC

VOLUME /data
WORKDIR /data
EXPOSE 8095

# The check follows PATHWATCH_LISTEN, so changing the port needs no extra
# setup. If you enable built-in TLS in pathwatch.yaml the plain-HTTP check
# will fail; in that case override the healthcheck in your compose file.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/pathwatch-healthcheck"]

ENTRYPOINT ["/usr/local/bin/pathwatch"]
CMD ["run"]
