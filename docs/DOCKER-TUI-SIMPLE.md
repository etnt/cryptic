# Running Cryptic TUI Client in Docker - Quick Start

This guide shows how to run the Cryptic TUI (terminal UI) client in Docker to connect to a Cryptic server.

## What's Included

The Docker image runs `bin/cryptic --tui` which automatically:
- Starts an Erlang backend node with `cryptic_engine` and `cryptic_ws_client`
- Launches the Rust TUI connected via distributed Erlang  
- Manages authentication, connection lifecycle, and graceful shutdown

## Prerequisites

### 1. Server Connection Information

Get these details from your server administrator:
- Server hostname (e.g., `relay.example.com` or `cryptic-server`)
- Server port (typically `8443`)
- CA certificate

### 2. Generate Client Certificates

Use the `cryptic-onboard` tool to set up your client identity:

Use the `cryptic-onboard` tool to set up your client identity:

```bash
# Run the interactive onboarding wizard
bin/cryptic-onboard
```

This will:
1. Check/generate your GPG key
2. Export your public key for admin registration
3. Wait for admin confirmation
4. Request a certificate from the server

**Important**: Send your GPG fingerprint (displayed during setup) to your server administrator. They must register it before you can get a certificate.

This creates: `~/.cryptic/<username>/<servername>_<port>/certificates/`

### 3. Set Up Erlang Cookie

```bash
# Create cookie file
echo -n "cryptic_secret_cookie" > ~/.erlang.cookie
chmod 400 ~/.erlang.cookie
```

## Quick Start

### 1. Build the Client Image

```bash
docker-compose build cryptic-tui
```

### 2. Run TUI Client

```bash
# Connect to your server
TUI_USERNAME=alice \
CRYPTIC_SERVER_HOST=relay.example.com \
CRYPTIC_SERVER_PORT=8443 \
docker-compose run --rm cryptic-tui
```

**For local testing** with the default `cryptic-server` service:

```bash
# Start local server first (for testing only)
docker-compose up -d cryptic-server

# Run client
TUI_USERNAME=alice docker-compose run --rm cryptic-tui
```

## Environment Variables

The Docker setup maps to `bin/cryptic` script options:

| Docker Env Variable | `bin/cryptic` Option | Default | Description |
|---------------------|---------------------|---------|-------------|
| `CRYPTIC_USERNAME` | `-u, --username` | `alice` | Your username |
| `CRYPTIC_SERVER_HOST` | `-s, --server-host` | `cryptic-server` | Server hostname |
| `CRYPTIC_SERVER_PORT` | `-p, --server-port` | `8443` | Server port |
| `CRYPTIC_NODE_NAME` | `--name` | `localhost` | Erlang node hostname |
| `CRYPTIC_ENABLE_DB` | `--enable-db` | `false` | Enable message history DB |
| `CRYPTIC_TUI_MODE` | `--tui` | `true` | Run in TUI mode |

### Example: Enable Message History

```bash
TUI_USERNAME=alice \
CRYPTIC_ENABLE_DB=true \
docker-compose run --rm cryptic-tui
```

### Example: Different Server

```bash
TUI_USERNAME=bob \
CRYPTIC_SERVER_HOST=relay.example.com \
CRYPTIC_SERVER_PORT=9443 \
docker-compose run --rm cryptic-tui
```

## Volume Mounts

The Docker Compose file automatically mounts:

1. **Entire .cryptic directory** (read-write):
   ```
   ~/.cryptic → /home/cryptic/.cryptic
   ```
   This contains:
   - `<username>/<server>_<port>/certificates/` - mTLS certificates
   - `<username>/<server>_<port>/keys.encrypted` - Encrypted identity keys
   - `<username>/<server>_<port>/sessions/` - Double Ratchet session states
   - `<username>/<server>_<port>/cryptic_chat.db` - SQLite message history (if `--enable-db`)
   - `logs/` - Application log files

2. **Erlang Cookie** (read-only):
   ```
   ~/.erlang.cookie → /home/cryptic/.erlang.cookie
   ```

### Directory Structure

Your `~/.cryptic` directory will look like:

```
~/.cryptic/
├── alice/
│   └── cryptic-server_8443/
│       ├── certificates/
│       │   ├── alice.crt          # Client certificate
│       │   ├── alice.key          # Private key (mode 600)
│       │   └── ca.crt             # CA certificate
│       ├── gpg_secret_key.asc     # GPG secret key for auto-renewal
│       ├── keys.encrypted         # Identity keys (X3DH)
│       ├── sessions/              # Double Ratchet states
│       │   ├── bob.session
│       │   └── charlie.session
│       ├── cryptic_chat.db        # Message history (optional)
│       └── cryptic_chat.db-wal    # SQLite WAL file
└── logs/
    └── cryptic-tui.log.YYYY-MM-DD # Daily log files
```

### Why Read-Write Access?

The container needs write access to:
- **Save identity keys**: Generated on first run, encrypted with your passphrase
- **Update session states**: Double Ratchet state after each message
- **Store message history**: SQLite database (if `--enable-db`)
- **Write logs**: Debugging and audit trail

### Permission Considerations

The container runs as user `cryptic` (non-root). If you encounter permission issues:

```bash
# Check ownership of your .cryptic directory
ls -la ~/.cryptic/

# If needed, ensure your user can read/write
chmod -R u+rwX ~/.cryptic/
```

**Note**: On Linux, you may need to match UIDs. On macOS/Windows with Docker Desktop, file permissions are handled automatically.

## Common Tasks

### Multiple Users at Once

```bash
# Terminal 1: Alice
TUI_USERNAME=alice docker-compose run --rm --name alice-client cryptic-tui

# Terminal 2: Bob  
TUI_USERNAME=bob docker-compose run --rm --name bob-client cryptic-tui
```

### Debug Mode

```bash
# Start with bash shell
docker-compose run --rm cryptic-tui /bin/bash

# Inside container:
cd /opt/cryptic
bin/cryptic --tui  # Run manually
```

### View Logs

```bash
# TUI logs
docker-compose exec cryptic-tui ls -la /home/cryptic/.cryptic/logs/

# Server logs
docker-compose logs -f cryptic-server
```

## Troubleshooting

### "Cannot connect to server"

1. Verify you can reach the server from the container:
   ```bash
   docker-compose run --rm cryptic-tui ping relay.example.com
   ```

2. Check server port is open:
   ```bash
   docker-compose run --rm cryptic-tui nc -zv relay.example.com 8443
   ```

3. Verify certificates exist:
   ```bash
   ls -la ~/.cryptic/$TUI_USERNAME/relay.example.com_8443/certificates/
   ```

Contact your server administrator if the server appears unreachable.

### "Certificate path not found"

The certificate path must match your server's hostname. For example, if connecting to `relay.example.com:8443`:

```bash
# Correct path structure:
~/.cryptic/alice/relay.example.com_8443/certificates/
  ├── alice.crt
  ├── alice.key
  └── ca.crt
```

If certificates are in the wrong location, re-run:
```bash
bin/cryptic-onboard
```

### "Erlang cookie mismatch"

Ensure cookies match:
```bash
# Check your cookie
cat ~/.erlang.cookie

# Should match server's cookie (default: cryptic_secret_cookie)
```

### "Permission denied" on .cryptic directory

The container runs as user `cryptic`. If you see permission errors:

```bash
# Check ownership
ls -la ~/.cryptic/

# Ensure you have read/write access
chmod -R u+rwX ~/.cryptic/

# On Linux, if UID mismatch issues persist:
# The container uses UID 100 (Alpine's cryptic user)
# Your host user may be UID 1000
# Docker Desktop on macOS/Windows handles this automatically
```

### Database files not persisting

If using `--enable-db` and messages don't save:

```bash
# Check the database file exists
ls -la ~/.cryptic/*/cryptic-server_8443/cryptic_chat.db

# Verify mount inside container
docker-compose exec cryptic-tui ls -la /home/cryptic/.cryptic/

# Ensure write permissions
chmod -R u+w ~/.cryptic/*/cryptic-server_8443/
```

### Session states not loading

Session files are stored in `~/.cryptic/<username>/<server>/sessions/`:

```bash
# Check session files
ls -la ~/.cryptic/alice/cryptic-server_8443/sessions/

# Should contain files like: bob.session, charlie.session
# These are encrypted Double Ratchet states
```

## Keyboard Shortcuts

Once running:

- `Ctrl+Q` - Quit
- `Tab` - Switch tabs
- `Enter` - Send message / Select user
- `PageUp`/`PageDown` - Scroll message history
- `Ctrl+A` / `Ctrl+E` - Move to start/end of line

## Advanced: Custom Configuration

### Using .env File

Create `.env` in project root:

```bash
TUI_USERNAME=alice
CRYPTIC_ENABLE_DB=true
```

Then:
```bash
docker-compose run --rm cryptic-tui
```

### Using docker-compose.override.yml

```yaml
# docker-compose.override.yml
services:
  cryptic-tui:
    environment:
      - CRYPTIC_USERNAME=myuser
      - CRYPTIC_ENABLE_DB=true
    volumes:
      - ~/.cryptic/myuser/cryptic-server_8443/certificates:/home/cryptic/.cryptic/myuser/cryptic-server_8443/certificates:ro
```

## How It Works

The Dockerfile:
1. Builds Rust TUI binary from `cryptic-tui/` subdirectory
2. Compiles Erlang application from `src/`
3. Copies `bin/cryptic` launcher script
4. Sets environment variables matching script options
5. Runs: `bin/cryptic --tui` (which starts both backend and UI)

The `bin/cryptic` script handles:
- Starting Erlang node with correct name and cookie
- Loading cryptic application modules
- Starting `cryptic_console_starter`
- Launching `cryptic-tui` binary connected to the Erlang node

## Related Documentation

- [Full Docker TUI Guide](DOCKER-TUI.md) - Comprehensive reference
- [Cryptic TUI README](../cryptic-tui/README.md) - TUI features and usage
- [Docker Setup Guide](DOCKER.md) - Server deployment
- [Event Bus Architecture](../AGENTS.md) - System architecture
