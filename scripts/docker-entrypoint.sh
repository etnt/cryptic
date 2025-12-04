#!/bin/sh
set -e

# Ensure required directories exist (in case volumes are mounted empty)
mkdir -p /opt/cryptic/data/ca
mkdir -p /opt/cryptic/logs
mkdir -p /opt/cryptic/certs

# Fix ownership of mounted volumes (they may be created as root)
chown -R cryptic:cryptic /opt/cryptic/data
chown -R cryptic:cryptic /opt/cryptic/logs

# Note: Certificate files at /opt/cryptic/certs/ are bind-mounted as read-only
# Ensure they have correct permissions on the HOST before mounting:
#   chmod 644 priv/ssl/*.{crt,key}

# Ensure priv/ssl directory exists for CA cert/key mounts
# The release path includes version, but we'll create under all lib versions
for libdir in /opt/cryptic/lib/cryptic-*/; do
    if [ -d "$libdir" ]; then
        mkdir -p "${libdir}priv/ssl"
        # Only chown the directory, not the read-only mounted files inside
        chown cryptic:cryptic "${libdir}priv/ssl" 2>/dev/null || true
        chown cryptic:cryptic "${libdir}priv" 2>/dev/null || true
    fi
done

# Also create priv/ssl in the working directory since config uses relative paths
mkdir -p /opt/cryptic/priv/ssl

# Copy CA cert/key files from mounted certs directory to priv/ssl
# The application config uses relative path "priv/ssl/ca.crt"
if [ -f "/opt/cryptic/certs/ca.crt" ] && [ -f "/opt/cryptic/certs/ca.key" ]; then
    echo "DEBUG: Copying CA files from /opt/cryptic/certs/ to priv/ssl/"
    cp /opt/cryptic/certs/ca.crt /opt/cryptic/priv/ssl/
    cp /opt/cryptic/certs/ca.key /opt/cryptic/priv/ssl/
    chown cryptic:cryptic /opt/cryptic/priv/ssl/*
else
    echo "WARNING: CA certificate files not found in /opt/cryptic/certs/"
    echo "  Expected: /opt/cryptic/certs/ca.crt and /opt/cryptic/certs/ca.key"
    echo "  Run certificate generation first or mount the files."
fi

# Debug: Show directory permissions
echo "DEBUG: /opt/cryptic/data permissions:"
ls -ld /opt/cryptic/data
echo "DEBUG: /opt/cryptic/data/ca permissions:"
ls -ld /opt/cryptic/data/ca
echo "DEBUG: /opt/cryptic/data/ca contents:"
ls -la /opt/cryptic/data/ca/ || echo "Directory empty or not readable"
echo "DEBUG: Environment CRYPTIC_CA_DB_FILE=${CRYPTIC_CA_DB_FILE}"
echo "DEBUG: Environment CRYPTIC_DEBUG=${CRYPTIC_DEBUG}"
echo "DEBUG: Test file creation:"
su-exec cryptic touch /opt/cryptic/data/ca/test.txt && echo "SUCCESS" || echo "FAILED"

# Switch to cryptic user and execute the main command
# Explicitly preserve environment variables that the application needs
exec su-exec cryptic env \
    CRYPTIC_SERVER_HOST="${CRYPTIC_SERVER_HOST}" \
    CRYPTIC_SERVER_PORT="${CRYPTIC_SERVER_PORT}" \
    CRYPTIC_SERVER_CERT="${CRYPTIC_SERVER_CERT}" \
    CRYPTIC_SERVER_KEY="${CRYPTIC_SERVER_KEY}" \
    CRYPTIC_CA_CERT="${CRYPTIC_CA_CERT}" \
    CRYPTIC_CA_DB_FILE="${CRYPTIC_CA_DB_FILE}" \
    CRYPTIC_EVENT_HANDLERS="${CRYPTIC_EVENT_HANDLERS}" \
    CRYPTIC_DEBUG="${CRYPTIC_DEBUG}" \
    "$@"
