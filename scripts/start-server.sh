#!/bin/bash
#
# start-server.sh
# Start the Cryptic server with optional configuration
#
# Usage: start-server.sh [-s, --server-host HOST] [-p, --server-port PORT] [-d, --daemon] [-h, --help]
#
# Options:
#   -s, --server-host HOST  Server host address (default: localhost)
#   -p, --server-port PORT  Server port number (default: 8080)
#   -d, --daemon            Run server in daemon mode (detached)
#   -h, --help              Show this help message
#
# Examples:
#   ./start-server.sh                                    # localhost:8443
#   ./start-server.sh -h 0.0.0.0 -p 9000                 # Short options
#   ./start-server.sh --server-host 0.0.0.0 --server-port 9000
#   ./start-server.sh -d                                 # Run in background
#   ./start-server.sh -h 0.0.0.0 -d                      # Combine short options

# Get absolute path to project root (parent directory of scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default values
SERVER_HOST="localhost"
SERVER_PORT="8443"
DAEMON_MODE=false
NODE_NAME="crypticsrv@localhost"

# Function to display usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Start Cryptic server with WebSocket mTLS support.

Options:
    -s, --server-host HOST    Server host/IP to bind to (default: localhost)
    -p, --server-port PORT    Server port to listen on (default: 8443)
    --sname NODE              Erlang node name (default: crypticsrv@localhost)
    -d, --daemon              Run server as detached background process
    -h, --help                Display this help message and exit

Environment Variables:
    CRYPTIC_SERVER_CERT   Path to server certificate (default: CA/certs/server.crt)
    CRYPTIC_SERVER_KEY    Path to server private key (default: CA/private/server.key)
    CRYPTIC_CA_CERT       Path to CA certificate (default: CA/certs/ca.crt)
    CRYPTIC_EVENT_HANDLERS Event handlers to load (default: cryptic_file_logger)

Examples:
    # Start on localhost:8443
    $0

    # Start on all interfaces, port 9000 (short options)
    $0 -s 0.0.0.0 -p 9000

    # Start on all interfaces, port 9000 (long options)
    $0 --server-host 0.0.0.0 --server-port 9000

    # Start with custom node name
    $0 --sname mysrv@localhost

    # Start as daemon in background
    $0 -d

    # Combine options
    $0 -s 0.0.0.0 -p 9443 --sname myserver@localhost -d

EOF
}

# Parse command-line arguments
# Note: macOS uses BSD getopt which doesn't support long options,
# so we handle them manually
while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--server-host)
            SERVER_HOST="$2"
            shift 2
            ;;
        -p|--server-port)
            SERVER_PORT="$2"
            shift 2
            ;;
        --sname)
            NODE_NAME="$2"
            shift 2
            ;;
        -d|--daemon)
            DAEMON_MODE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            echo "Use -h or --help for usage information." >&2
            exit 1
            ;;
        *)
            echo "Error: Unexpected argument: $1" >&2
            echo "Use -h or --help for usage information." >&2
            exit 1
            ;;
    esac
done

# Set default certificate paths if not already set (use absolute paths)
export CRYPTIC_SERVER_CERT="${CRYPTIC_SERVER_CERT:-$PROJECT_ROOT/priv/ssl/server.crt}"
export CRYPTIC_SERVER_KEY="${CRYPTIC_SERVER_KEY:-$PROJECT_ROOT/priv/ssl/server.key}"
export CRYPTIC_CA_CERT="${CRYPTIC_CA_CERT:-$PROJECT_ROOT/priv/ssl/ca.crt}"

# Set server host and port via environment variables
export CRYPTIC_SERVER_HOST="${CRYPTIC_SERVER_HOST:-$SERVER_HOST}"
export CRYPTIC_SERVER_PORT="${CRYPTIC_SERVER_PORT:-$SERVER_PORT}"

echo "Cryptic Server Configuration:"
echo "  Node Name:   $NODE_NAME"
echo "  Server Host: $CRYPTIC_SERVER_HOST"
echo "  Server Port: $CRYPTIC_SERVER_PORT"
echo "  Server Cert: $CRYPTIC_SERVER_CERT"
echo "  Server Key:  $CRYPTIC_SERVER_KEY"
echo "  CA Cert:     $CRYPTIC_CA_CERT"

# Enable file logging by default (can be overridden)
export CRYPTIC_EVENT_HANDLERS="${CRYPTIC_EVENT_HANDLERS:-cryptic_file_logger}"
echo "  Event Handlers: $CRYPTIC_EVENT_HANDLERS"
echo ""

echo "Starting Cryptic application with WebSocket mTLS..."

# Build the erl command with common options
ERL_OPTS="-sname $NODE_NAME -pa $PROJECT_ROOT/_build/default/lib/*/ebin"

# Erlang code to run
ERL_CODE="
application:ensure_all_started(cryptic),
timer:sleep(1000),
inet:i(),
io:format(\"~nServer running!~n\"),
io:format(\"   WebSocket mTLS:   wss://$CRYPTIC_SERVER_HOST:$CRYPTIC_SERVER_PORT/ws~n\"),
io:format(\"   Press Ctrl+C to stop~n~n\"),
timer:sleep(infinity).
"

if [ "$DAEMON_MODE" = true ]; then
    # Run as detached daemon
    echo "Starting server in daemon mode..."

    # Create log directory if it doesn't exist
    mkdir -p "$PROJECT_ROOT/logs"

    LOG_FILE="$PROJECT_ROOT/logs/server.log"
    PID_FILE="$PROJECT_ROOT/logs/server.pid"

    # Start detached Erlang node with heart for auto-restart
    erl -detached \
        -heart \
        $ERL_OPTS \
        -kernel error_logger '{file,"'$LOG_FILE'"}' \
        -eval "$ERL_CODE" &

    # Save the PID
    echo $! > "$PID_FILE"

    echo ""
    echo "Server started in daemon mode"
    echo "  PID: $(cat $PID_FILE)"
    echo "  Log file: $LOG_FILE"
    echo ""
    echo "To stop the server, run:"
    echo "  kill \$(cat $PID_FILE)"
    echo "  rm $PID_FILE"
    echo ""
else
    # Run in foreground (interactive mode)
    erl $ERL_OPTS -eval "$ERL_CODE"
fi
