# Running Cryptic TUI Client in Docker

This guide explains how to run the Cryptic terminal UI (TUI) client in a Docker container. The TUI is a Rust-based interactive terminal interface built with Ratatui that connects to a Cryptic Erlang backend.

## Overview

The `cryptic-tui` Docker image uses the `bin/cryptic` script with the `--tui` flag, which automatically:
1. **Starts an Erlang backend node** - Runs `cryptic_engine`, `cryptic_ws_client`, and `cryptic_event_bus`
2. **Launches the Rust TUI** - Connects via distributed Erlang protocol to the backend
3. **Manages the lifecycle** - Handles node naming, cookie authentication, and graceful shutdown

This is exactly the same as running `bin/cryptic --tui` on your local machine, but containerized.

## Architecture in Docker

```
┌─────────────────────────────────────────────────────────────┐
│  Docker Container: cryptic-tui                              │
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │  bin/cryptic --tui (launcher script)               │    │
│  │                                                     │    │
│  │  ┌──────────────────┐   ┌─────────────────────┐  │    │
│  │  │  Rust TUI        │   │  Erlang Backend     │  │    │
│  │  │  (cryptic-tui)   │◄─►│  (cryptic@hostname) │  │    │
│  │  │                  │   │                     │  │    │
│  │  │  - UI Rendering  │   │  - cryptic_engine   │  │    │
│  │  │  - User Input    │   │  - cryptic_ws_client│  │    │
│  │  │  - Formatting    │   │  - event_bus_bridge │  │    │
│  │  └──────────────────┘   └──────────┬──────────┘  │    │
│  └───────────────────────────────────────┼───────────┘    │
│                                          │                │
└──────────────────────────────────────────┼────────────────┘
                                           │ WebSocket mTLS
                                           │
                   ┌───────────────────────▼────────────────┐
                   │  Docker Network: cryptic-network       │
                   └───────────────────────┬────────────────┘
                                           │
┌──────────────────────────────────────────▼─────────────────┐
│  Docker Container: cryptic-server                          │
│  - WebSocket server (port 8443)                            │
│  - Certificate authority                                   │
└────────────────────────────────────────────────────────────┘
```

## Prerequisites

### 1. Generate Certificates

Before running the TUI client, you need valid mTLS certificates. Use the `cryptic-onboard` tool:

```bash
# Step 1: Export GPG key for admin registration
bin/cryptic-onboard export-gpg

# Step 2: Admin registers your GPG key
# (Contact your Cryptic administrator)

# Step 3: Request certificate from server
# IMPORTANT: Use 'cryptic-server' as hostname (Docker service name)
bin/cryptic-onboard request https://cryptic-server:8443
```

This creates certificates in `~/.cryptic/<username>/cryptic-server_8443/certificates/`:
- `<username>.crt` - Client certificate
- `<username>.key` - Private key
- `ca.crt` - CA certificate

**Note**: The certificate path must use `cryptic-server` (the Docker service name) not `localhost`, so the paths match what the container expects.

### 2. Set Erlang Cookie

The Erlang cookie must match between client and server nodes. Create `~/.erlang.cookie`:

```bash
echo -n "cryptic_secret_cookie" > ~/.erlang.cookie
chmod 400 ~/.erlang.cookie
```

Or use a `.env` file (recommended for Docker Compose):
```bash
# Create .env file in project root
echo "ERLANG_COOKIE=your_secret_cookie_here" > .env
```

**Option C: Docker Compose override**
```yaml
# docker-compose.override.yml
services:
  cryptic-server:
    environment:
      - ERLANG_COOKIE=your_secret_cookie_here
  cryptic-tui:
    environment:
      - ERLANG_COOKIE=your_secret_cookie_here
```

## Quick Start

### Start Server and Client Together

```bash
# Build both images
docker-compose build

# Start server in background
docker-compose up -d cryptic-server

# Wait for server to be healthy (check with docker-compose ps)
docker-compose ps

# Start TUI client (interactive)
docker-compose run --rm cryptic-tui
```

### Start TUI Client for Specific User

```bash
# For user 'bob'
TUI_USERNAME=bob docker-compose run --rm cryptic-tui
```

### Attach to Running TUI

If you want to start TUI in detached mode and attach later:

```bash
# Start detached
docker-compose up -d cryptic-tui

# Attach to running container
docker attach cryptic-tui

# Detach without stopping: Ctrl+P, Ctrl+Q
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TUI_USERNAME` | `alice` | Username for certificate lookup |
| `TUI_NODE_NAME` | `tui` | Short name for Erlang node |
| `ERLANG_NODE` | `cryptic@cryptic-server` | Target Erlang node to connect to |
| `ERLANG_COOKIE` | `cryptic_secret_cookie` | Erlang distribution cookie |
| `TERM` | `xterm-256color` | Terminal type |

### Volume Mounts

**Required**:
```yaml
volumes:
  # User certificates (adjust path for your username)
  - ~/.cryptic/alice/localhost_8443/certificates:/home/cryptic/.cryptic/alice/certificates:ro
```

**Optional**:
```yaml
volumes:
  # Separate CA cert
  - ./priv/ssl/ca.crt:/home/cryptic/.cryptic/ca.crt:ro
  
  # Logs directory (named volume)
  - cryptic-tui-logs:/home/cryptic/.cryptic/logs
  
  # Custom Erlang cookie
  - ~/.erlang.cookie:/home/cryptic/.erlang.cookie:ro
```

## Usage Examples

### Example 1: Run with Custom Username

```bash
# User 'bob' connecting to localhost:8443
TUI_USERNAME=bob \
  docker-compose run --rm \
  -v ~/.cryptic/bob/localhost_8443/certificates:/home/cryptic/.cryptic/bob/certificates:ro \
  cryptic-tui
```

### Example 2: Connect to Remote Server

```bash
# Adjust ERLANG_NODE to match remote server
docker-compose run --rm \
  -e ERLANG_NODE=cryptic@remote.example.com \
  -e TUI_USERNAME=alice \
  -v ~/.cryptic/alice/remote.example.com_8443/certificates:/home/cryptic/.cryptic/alice/certificates:ro \
  cryptic-tui
```

### Example 3: Run Multiple Clients

```bash
# Terminal 1: Alice
TUI_USERNAME=alice TUI_NODE_NAME=tui_alice docker-compose run --rm --name alice-client cryptic-tui

# Terminal 2: Bob
TUI_USERNAME=bob TUI_NODE_NAME=tui_bob docker-compose run --rm --name bob-client cryptic-tui
```

### Example 4: Debug Mode with Shell Access

```bash
# Start container with bash shell
docker-compose run --rm cryptic-tui /bin/bash

# Inside container:
# - Check Erlang node: bin/cryptic ping
# - View logs: tail -f ~/.cryptic/logs/cryptic-tui.log.*
# - Run TUI manually: cryptic-tui --node cryptic@cryptic-server --cookie $ERLANG_COOKIE
```

## Keyboard Shortcuts

Once the TUI is running:

### Global
- `Ctrl+Q` - Quit application
- `Tab` - Next tab
- `Shift+Tab` - Previous tab

### Chat Tab
- `↑/↓` - Select user
- `Enter` - Open chat / Send message
- `PageUp` / `Ctrl+U` - Scroll up (load older messages)
- `PageDown` / `Ctrl+D` - Scroll down
- `Home` - Jump to beginning of conversation
- `End` - Jump to latest messages
- `Esc` - Clear input

### Text Editing (Emacs-style)
- `Ctrl+A` - Move to beginning of line
- `Ctrl+E` - Move to end of line
- `Ctrl+B` / `←` - Move cursor left
- `Ctrl+F` / `→` - Move cursor right
- `Backspace` - Delete character before cursor

## Troubleshooting

### Issue: "Cannot connect to Erlang node"

**Solutions**:
1. Verify server is running: `docker-compose ps cryptic-server`
2. Check network connectivity: `docker-compose exec cryptic-tui ping cryptic-server`
3. Verify Erlang cookie matches on both nodes
4. Check EPMD is running: `docker-compose exec cryptic-server epmd -names`

### Issue: "Certificate not found"

**Solutions**:
1. Verify certificate path matches your username:
   ```bash
   ls -la ~/.cryptic/$TUI_USERNAME/localhost_8443/certificates/
   ```
2. Ensure certificates are mounted correctly in docker-compose.yml
3. Re-run `cryptic-onboard request` if certificates are missing

### Issue: "Terminal not rendering correctly"

**Solutions**:
1. Ensure terminal supports 256 colors: `echo $TERM`
2. Try different TERM value:
   ```bash
   docker-compose run --rm -e TERM=xterm cryptic-tui
   ```
3. Increase terminal window size (Ratatui needs minimum dimensions)

### Issue: "Permission denied on volumes"

**Solutions**:
1. Check file ownership:
   ```bash
   ls -la ~/.cryptic/*/certificates/
   ```
2. Fix permissions:
   ```bash
   chmod 600 ~/.cryptic/*/certificates/*.key
   chmod 644 ~/.cryptic/*/certificates/*.crt
   ```

### View Logs

```bash
# TUI logs
docker-compose exec cryptic-tui tail -f /home/cryptic/.cryptic/logs/cryptic-tui.log.*

# Server logs
docker-compose logs -f cryptic-server

# Erlang client node logs (inside TUI container)
docker-compose exec cryptic-tui tail -f /opt/cryptic/erlang/log/erlang.log.*
```

## Advanced Configuration

### Custom docker-compose.override.yml

Create `docker-compose.override.yml` for local customizations:

```yaml
services:
  cryptic-tui:
    environment:
      - TUI_USERNAME=myuser
      - ERLANG_COOKIE=my_custom_cookie
    volumes:
      - ~/.cryptic/myuser/myserver_8443/certificates:/home/cryptic/.cryptic/myuser/certificates:ro
      - ./custom-config:/home/cryptic/.config:ro
```

### Build Custom Image

```bash
# Build with custom tags
docker build -f Dockerfile.tui -t mycrypto/tui:latest .

# Build without cache
docker build --no-cache -f Dockerfile.tui -t cryptic-tui:latest .
```

### Run Outside Docker Compose

```bash
# Build image
docker build -f Dockerfile.tui -t cryptic-tui:latest .

# Create network
docker network create cryptic-net

# Run server (in background)
docker run -d \
  --name cryptic-server \
  --network cryptic-net \
  -p 8443:8443 \
  -v ./priv/ssl:/opt/cryptic/certs:ro \
  cryptic-server:latest

# Run TUI (interactive)
docker run -it --rm \
  --name cryptic-tui \
  --network cryptic-net \
  -e ERLANG_NODE=cryptic@cryptic-server \
  -e ERLANG_COOKIE=my_cookie \
  -e TUI_USERNAME=alice \
  -v ~/.cryptic/alice/localhost_8443/certificates:/home/cryptic/.cryptic/alice/certificates:ro \
  cryptic-tui:latest
```

## Performance Considerations

### Container Resources

For optimal TUI performance:

```yaml
services:
  cryptic-tui:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### Network Latency

- **Local Docker**: Minimal latency (<1ms)
- **Docker on VM**: May see 5-10ms latency
- **Remote Docker**: Network latency applies

## Security Notes

1. **Erlang Cookie**: Treat as a password. Don't commit to version control.
2. **Certificate Keys**: Mounted read-only (`:ro`) to prevent modification.
3. **User Isolation**: Container runs as non-root `cryptic` user (UID/GID created at build time).
4. **mTLS**: All WebSocket connections use mutual TLS authentication.
5. **Logs**: May contain debugging info. Review before sharing.

## Next Steps

- [Read TUI documentation](../cryptic-tui/README.md)
- [Understand event bus architecture](../AGENTS.md)
- [Set up CI/CD for Docker builds](.github/workflows/)
- [Deploy to production with Docker Swarm or Kubernetes](docs/DEPLOYMENT.md)

## Related Documentation

- [Cryptic TUI README](../cryptic-tui/README.md)
- [Docker Setup Guide](DOCKER.md)
- [GPG Bootstrap Process](GPG-BOOTSTRAP.md)
- [X3DH Protocol Explanation](X3DH-EXPLAINED.md)
