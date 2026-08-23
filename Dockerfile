# Multi-stage Dockerfile for Cryptic Server
# Based on https://github.com/erlang/docker-erlang-example

# Build stage
FROM erlang:28.1-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    make \
    gcc \
    g++ \
    libc-dev \
    openssl-dev \
    libsodium-dev \
    argon2-dev \
    sqlite-dev \
    pkgconf

# Set working directory
WORKDIR /buildroot

# Copy rebar files first for dependency caching
COPY rebar.config rebar.lock ./

# Get dependencies (this layer will be cached if dependencies don't change)
RUN rebar3 get-deps

# Copy source code
COPY . .

# Build NIF with correct architecture flags
RUN cd c_src && \
    make clean && \
    UNAME_ARCH=aarch64 make

# Build release
RUN rebar3 as prod release

# Runtime stage - use same Erlang version as builder for consistency
FROM erlang:28.1-alpine

# Install runtime dependencies
RUN apk add --no-cache \
    libsodium \
    argon2-libs \
    sqlite-libs \
    su-exec \
    netcat-openbsd \
    openssl

# Create cryptic user and group
RUN addgroup -S cryptic && adduser -S cryptic -G cryptic

# Set working directory
WORKDIR /opt/cryptic

# Copy the release from builder
COPY --from=builder /buildroot/_build/prod/rel/cryptic ./

# Copy entrypoint + operator helper scripts from scripts directory
COPY scripts/docker-entrypoint.sh /usr/local/bin/
COPY scripts/generate-mtls-certs.sh /usr/local/bin/
COPY scripts/cryptic-hash-admin-password.escript /usr/local/bin/cryptic-hash-admin-password
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    /usr/local/bin/generate-mtls-certs.sh \
    /usr/local/bin/cryptic-hash-admin-password

# Create directories for runtime data (including CA DB)
RUN mkdir -p /opt/cryptic/certs /opt/cryptic/logs /opt/cryptic/data/ca && \
    chown -R cryptic:cryptic /opt/cryptic

# Don't switch to cryptic user yet - entrypoint needs root to fix volume permissions
# USER cryptic will be set by entrypoint after fixing permissions

# Expose WebSocket TLS port and the web admin HTTPS port
EXPOSE 8443 8444

# Set environment variables with defaults
# Note: Certificate paths are configured in sys.config as relative paths
# CRYPTIC_SERVER_DIR will be prepended by cryptic_lib:get_server_file/2
ENV CRYPTIC_SERVER_HOST=0.0.0.0 \
    CRYPTIC_SERVER_PORT=8443 \
    CRYPTIC_EVENT_HANDLERS=cryptic_file_logger \
    CRYPTIC_WEBADMIN_ENABLED=true \
    CRYPTIC_WEBADMIN_PORT=8444

# Health check: the WebSocket port must always be listening; when the web admin
# endpoint is enabled its port must be up too.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD nc -z localhost ${CRYPTIC_SERVER_PORT} && { \
        case "${CRYPTIC_WEBADMIN_ENABLED}" in \
            1|true|yes|on) nc -z localhost ${CRYPTIC_WEBADMIN_PORT} ;; \
            *) true ;; \
        esac; } || exit 1

# Use entrypoint to ensure directories exist
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Start the server using the release
CMD ["bin/cryptic", "foreground"]
