#!/bin/sh
set -e

# Set default CRYPTIC_SERVER_DIR to /opt/cryptic/server_data if not already set
# This will contain all server data: priv/, logs/, and data/
# Note: /opt/cryptic contains the Erlang release (bin/, lib/, etc.)
if [ -z "${CRYPTIC_SERVER_DIR}" ]; then
    CRYPTIC_SERVER_DIR="/opt/cryptic/server_data"
    export CRYPTIC_SERVER_DIR
fi

# Ensure all required directories exist under CRYPTIC_SERVER_DIR
mkdir -p "${CRYPTIC_SERVER_DIR}/data/ca"
mkdir -p "${CRYPTIC_SERVER_DIR}/logs"
mkdir -p "${CRYPTIC_SERVER_DIR}/priv/ssl"
mkdir -p "${CRYPTIC_SERVER_DIR}/priv/ca/bootstrap"

echo "INFO: CRYPTIC_SERVER_DIR is set to ${CRYPTIC_SERVER_DIR}"
echo "INFO: Expected structure:"
echo "  ${CRYPTIC_SERVER_DIR}/priv/ssl/ca.crt        - CA certificate"
echo "  ${CRYPTIC_SERVER_DIR}/priv/ssl/ca.key        - CA private key"
echo "  ${CRYPTIC_SERVER_DIR}/priv/ssl/server.crt    - Server certificate"
echo "  ${CRYPTIC_SERVER_DIR}/priv/ssl/server.key    - Server private key"
echo "  ${CRYPTIC_SERVER_DIR}/priv/ca/bootstrap/*.gpg - Bootstrap GPG keys"
echo "  ${CRYPTIC_SERVER_DIR}/data/                   - Database files"
echo "  ${CRYPTIC_SERVER_DIR}/logs/                   - Log files"

# Check if CA certificates exist
if [ ! -f "${CRYPTIC_SERVER_DIR}/priv/ssl/ca.crt" ] || [ ! -f "${CRYPTIC_SERVER_DIR}/priv/ssl/ca.key" ]; then
    echo "ERROR: CA certificates not found!"
    echo "Please generate certificates before starting the server:"
    echo ""
    echo "  docker run -it --rm \\"
    echo "    --entrypoint '' \\"
    echo "    -v \$(pwd):/opt/cryptic/server_data \\"
    echo "    -e CRYPTIC_SERVER_DIR=/opt/cryptic/server_data \\"
    echo "    <image-name> \\"
    echo "    sh -c 'DIR=\"\${CRYPTIC_SERVER_DIR}/priv/ssl\" generate-mtls-certs.sh'"
    echo ""
    exit 1
else
    echo "INFO: CA certificates found"
fi

# Fix ownership of mounted volumes (they may be created as root)
chown -R cryptic:cryptic "${CRYPTIC_SERVER_DIR}/data" 2>/dev/null || true
chown -R cryptic:cryptic "${CRYPTIC_SERVER_DIR}/logs" 2>/dev/null || true

# Debug: Show directory structure and permissions
if [ "${CRYPTIC_DEBUG}" = "true" ]; then
    echo "DEBUG: ${CRYPTIC_SERVER_DIR}/data permissions:"
    ls -ld "${CRYPTIC_SERVER_DIR}/data"
    echo "DEBUG: ${CRYPTIC_SERVER_DIR}/data/ca permissions:"
    ls -ld "${CRYPTIC_SERVER_DIR}/data/ca"
    echo "DEBUG: ${CRYPTIC_SERVER_DIR}/data/ca contents:"
    ls -la "${CRYPTIC_SERVER_DIR}/data/ca/" || echo "Directory empty or not readable"

    echo "DEBUG: ${CRYPTIC_SERVER_DIR}/priv contents:"
    ls -laR "${CRYPTIC_SERVER_DIR}/priv" 2>/dev/null || echo "Directory not readable"

    echo "DEBUG: Environment variables:"
    echo "  CRYPTIC_SERVER_DIR=${CRYPTIC_SERVER_DIR}"
    echo "  CRYPTIC_CA_DB_FILE=${CRYPTIC_CA_DB_FILE}"
    echo "  CRYPTIC_DEBUG=${CRYPTIC_DEBUG}"
fi

# Switch to cryptic user and execute the main command
# Explicitly preserve environment variables that the application needs
exec su-exec cryptic env \
    CRYPTIC_SERVER_HOST="${CRYPTIC_SERVER_HOST}" \
    CRYPTIC_SERVER_PORT="${CRYPTIC_SERVER_PORT}" \
    CRYPTIC_SERVER_DIR="${CRYPTIC_SERVER_DIR}" \
    CRYPTIC_CA_DB_FILE="${CRYPTIC_CA_DB_FILE}" \
    CRYPTIC_EVENT_HANDLERS="${CRYPTIC_EVENT_HANDLERS}" \
    CRYPTIC_DEBUG="${CRYPTIC_DEBUG}" \
    "$@"
