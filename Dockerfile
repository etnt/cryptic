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
    sqlite-libs \
    gnupg \
    su-exec \
    netcat-openbsd

# Create cryptic user and group
RUN addgroup -S cryptic && adduser -S cryptic -G cryptic

# Set working directory
WORKDIR /opt/cryptic

# Copy the release from builder
COPY --from=builder /buildroot/_build/prod/rel/cryptic ./

# Copy entrypoint script from scripts directory
COPY scripts/docker-entrypoint.sh /usr/local/bin/
COPY scripts/generate-mtls-certs.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/generate-mtls-certs.sh

# Create directories for runtime data (including CA DB and bootstrap area)
RUN mkdir -p /opt/cryptic/certs /opt/cryptic/logs /opt/cryptic/data/ca /opt/cryptic/priv/ca/bootstrap && \
    chown -R cryptic:cryptic /opt/cryptic

# Don't switch to cryptic user yet - entrypoint needs root to fix volume permissions
# USER cryptic will be set by entrypoint after fixing permissions

# Expose WebSocket TLS port
EXPOSE 8443

# Set environment variables with defaults
ENV CRYPTIC_SERVER_HOST=0.0.0.0 \
    CRYPTIC_SERVER_PORT=8443 \
    CRYPTIC_SERVER_CERT=/opt/cryptic/certs/server.crt \
    CRYPTIC_SERVER_KEY=/opt/cryptic/certs/server.key \
    CRYPTIC_CA_CERT=/opt/cryptic/certs/ca.crt \
    CRYPTIC_CA_DB_FILE=/opt/cryptic/data/ca/cryptic_ca.db \
    CRYPTIC_EVENT_HANDLERS=cryptic_file_logger

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD nc -z localhost ${CRYPTIC_SERVER_PORT} || exit 1

# Use entrypoint to ensure directories exist
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Start the server using the release
CMD ["bin/cryptic", "foreground"]
