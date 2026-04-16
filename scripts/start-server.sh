#!/bin/bash
#
# start-server.sh
# Start the Cryptic server with optional configuration
#
# Usage: start-server.sh [-s, --server-host HOST] [-p, --server-port PORT] [-m, --mcp [PORT]] [-d, --daemon] [-h, --help]
#
# Options:
#   -s, --server-host HOST  Server host address (default: localhost)
#   -p, --server-port PORT  Server port number (default: 8080)
#   -m, --mcp [PORT]        Enable MCP admin endpoint (default port: 8081)
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
MCP_ENABLED=false
MCP_PORT="8081"
NODE_NAME="crypticsrv@localhost"

# Function to display usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Start Cryptic server with WebSocket mTLS support.

Options:
    -s, --server-host HOST    Server host/IP to bind to (default: localhost)
    -p, --server-port PORT    Server port to listen on (default: 8443)
    -m, --mcp [PORT]          Enable MCP admin endpoint on localhost (default port: 8081)
    --sname NODE              Erlang node name (default: crypticsrv@localhost)
    -d, --daemon              Run server as detached background process
    -h, --help                Display this help message and exit

Environment Variables:
    CRYPTIC_SERVER_CERT   Path to server certificate (default: CA/certs/server.crt)
    CRYPTIC_SERVER_KEY    Path to server private key (default: CA/private/server.key)
    CRYPTIC_CA_CERT       Path to CA certificate (default: CA/certs/ca.crt)
    CRYPTIC_EVENT_HANDLERS Event handlers to load (default: cryptic_file_logger)
    CRYPTIC_MCP_PORT      MCP admin endpoint port (default: 8081)

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

    # Enable MCP admin endpoint
    $0 --mcp

    # Enable MCP on custom port
    $0 --mcp 9081

    # Combine options
    $0 -s 0.0.0.0 -p 9443 --mcp --sname myserver@localhost -d

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
        -m|--mcp)
            MCP_ENABLED=true
            # Check if next arg is a port number (not another flag)
            if [[ -n "${2:-}" && "$2" =~ ^[0-9]+$ ]]; then
                MCP_PORT="$2"
                shift 2
            else
                shift
            fi
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

# Set MCP environment if enabled
if [ "$MCP_ENABLED" = true ]; then
    export CRYPTIC_MCP_PORT="${CRYPTIC_MCP_PORT:-$MCP_PORT}"
fi

echo "Cryptic Server Configuration:"
echo "  Node Name:   $NODE_NAME"
echo "  Server Host: $CRYPTIC_SERVER_HOST"
echo "  Server Port: $CRYPTIC_SERVER_PORT"
echo "  Server Cert: $CRYPTIC_SERVER_CERT"
echo "  Server Key:  $CRYPTIC_SERVER_KEY"
echo "  CA Cert:     $CRYPTIC_CA_CERT"
if [ "$MCP_ENABLED" = true ]; then
    echo "  MCP Admin:   http://127.0.0.1:$CRYPTIC_MCP_PORT/mcp/v1/admin"
else
    echo "  MCP Admin:   disabled (use --mcp to enable)"
fi

# Enable file logging by default (can be overridden)
export CRYPTIC_EVENT_HANDLERS="${CRYPTIC_EVENT_HANDLERS:-cryptic_file_logger}"
echo "  Event Handlers: $CRYPTIC_EVENT_HANDLERS"
echo ""

echo "Starting Cryptic application with WebSocket mTLS..."

# Build the erl command with common options
ERL_OPTS="-sname $NODE_NAME -pa $PROJECT_ROOT/_build/default/lib/*/ebin"

# Build MCP config snippet for Erlang
if [ "$MCP_ENABLED" = true ]; then
    MCP_ERL_CONFIG="application:set_env(cryptic, mcp_tcp_enabled, true), application:set_env(cryptic, mcp_tcp_port, $CRYPTIC_MCP_PORT),"
    MCP_STATUS_LINE="io:format(\"   MCP Admin:        http://127.0.0.1:$CRYPTIC_MCP_PORT/mcp/v1/admin~n\"),"
else
    MCP_ERL_CONFIG=""
    MCP_STATUS_LINE=""
fi

# Erlang code to run
ERL_CODE="
$MCP_ERL_CONFIG
application:ensure_all_started(cryptic),
timer:sleep(1000),
inet:i(),
io:format(\"~nServer running!~n\"),
io:format(\"   WebSocket mTLS:   wss://$CRYPTIC_SERVER_HOST:$CRYPTIC_SERVER_PORT/ws~n\"),
$MCP_STATUS_LINE
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
