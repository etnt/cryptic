# Docker Deployment Guide

This guide explains how to deploy the Cryptic client and or the
[server](#the-server) using Docker and Docker Compose.


## Quick Deployment

**Run the latest client image:**

[Demo](https://youtu.be/acNHqzHia3o?si=_4mQuE4KQooxb1UM)

```bash
# Get the latest Client docker image
docker pull ghcr.io/etnt/cryptic-tui:latest

# Run the Cryptic Onboarding script
#  1. Generate a GPG key pair (or use existing one from ~/.gnupg)
#  2. Export the generated key
#  3. Send the key and fingerprint to the admin
#  4. WAIT! - Do not exit the onboard script (the container will be gone) 
#  5. When admin has registered your key: Request a TLS certificate from server
#    If your server is running on localhost on your Host machine, specify:
#    cryptic-server as your server address (see the: `--add-host` below)
#  6. Exit the onboard script
# You should now see your certificates at ~/.cryptic/<user>/cryptic-server_<port>
#
# NOTE: ~/.gnupg is mounted so your GPG keyring is shared with the container.
#       This is required for automatic certificate renewal.
docker run -it --rm --name cryptic-client \
           -v ~/.cryptic:/home/cryptic/.cryptic \
           -v ~/.gnupg:/home/cryptic/.gnupg \
           --add-host=cryptic-server:host-gateway \
           ghcr.io/etnt/cryptic-tui:latest sh -c 'cryptic --onboard'

# Start the Cryptic client with your username (e.g `franz`)
# You'll be prompted for a Passphrase which is used to encrypt your local DB
docker run -it --rm --name cryptic-client \
           -v ~/.cryptic:/home/cryptic/.cryptic \
           -v ~/.gnupg:/home/cryptic/.gnupg \
           --add-host=cryptic-server:host-gateway \
           ghcr.io/etnt/cryptic-tui:latest sh -c 'cryptic -u franz --enable-db --tui'
```

**Run the latest server image:**

```bash
# Get the latest Server docker image
docker pull ghcr.io/etnt/cryptic:latest

# Setup the server certificates (one-time step)
# Creates ca.crt, ca.key, server.crt, server.key in ./priv/ssl/
mkdir -p priv/ssl priv/ca/bootstrap
docker run -it --rm \
  -v $(pwd)/priv/ssl:/opt/cryptic/certs \
  ghcr.io/etnt/cryptic:latest sh -c 'DIR=/opt/cryptic/certs generate-mtls-certs.sh'

# Bootstrap the first admin user BEFORE starting the server
# This creates a GPG key and exports it to priv/ca/bootstrap/
# The server will read this directory at startup to register the admin
docker run -it --rm \
  -v $(pwd)/priv/ca/bootstrap:/opt/cryptic/lib/cryptic-1.0.0/priv/ca/bootstrap:rw \
  -v ~/.gnupg:/home/cryptic/.gnupg:rw \
  ghcr.io/etnt/cryptic:latest sh -c 'bootstrap-admin alice'

# Run the server (requires certificates in ./priv/ssl/)
# Mounts:
#   - Server certs (ro): server.crt, server.key, ca.crt
#   - CA certs for issuance (ro): ca.crt, ca.key in release priv dir
#   - Bootstrap dir (ro): pre-registered admin GPG keys
#   - GPG keyring (rw): shared with host for signing operations
#   - Persistent volumes: logs and CA database
docker run -d \
  --name cryptic-server \
  -p 8443:8443 \
  -v $(pwd)/priv/ssl/server.crt:/opt/cryptic/certs/server.crt:ro \
  -v $(pwd)/priv/ssl/server.key:/opt/cryptic/certs/server.key:ro \
  -v $(pwd)/priv/ssl/ca.crt:/opt/cryptic/certs/ca.crt:ro \
  -v $(pwd)/priv/ssl/ca.crt:/opt/cryptic/lib/cryptic-1.0.0/priv/ssl/ca.crt:ro \
  -v $(pwd)/priv/ssl/ca.key:/opt/cryptic/lib/cryptic-1.0.0/priv/ssl/ca.key:ro \
  -v $(pwd)/priv/ca/bootstrap:/opt/cryptic/lib/cryptic-1.0.0/priv/ca/bootstrap:ro \
  -v ~/.gnupg:/home/cryptic/.gnupg:rw \
  -v cryptic-logs:/opt/cryptic/logs \
  -v cryptic-data:/opt/cryptic/data \
  -e CRYPTIC_SERVER_HOST=0.0.0.0 \
  ghcr.io/etnt/cryptic:latest

# Check server logs
docker logs -f cryptic-server

# Stop the server
docker stop cryptic-server && docker rm cryptic-server
```

### First Admin Bootstrap

The admin bootstrap happens **before** starting the server (see above). The `bootstrap-admin`
script creates a GPG key and exports it to the bootstrap directory, which the server reads
at startup.

**Now the admin can onboard** from their client machine:

```bash
docker run -it --rm --name cryptic-client \
  -v ~/.cryptic:/home/cryptic/.cryptic \
  -v ~/.gnupg:/home/cryptic/.gnupg \
  --add-host=cryptic-server:host-gateway \
  ghcr.io/etnt/cryptic-tui:latest sh -c 'cryptic --onboard'
```

During onboarding:
1. Generate a GPG key (or use existing one)
2. The fingerprint is already registered (from the bootstrap step)
3. Request your TLS certificate
4. Start using Cryptic!

Once the first admin has a certificate, they can register other users' GPG keys
through the admin interface, allowing those users to complete onboarding.

**Note**: If you need to bootstrap multiple admin users before starting the server,
run the bootstrap script multiple times before `docker run`:

```bash
# Bootstrap multiple admins (before starting server)
docker run -it --rm \
  -v $(pwd)/priv/ca/bootstrap:/opt/cryptic/lib/cryptic-1.0.0/priv/ca/bootstrap:rw \
  -v ~/.gnupg:/home/cryptic/.gnupg:rw \
  ghcr.io/etnt/cryptic:latest sh -c 'bootstrap-admin alice'

docker run -it --rm \
  -v $(pwd)/priv/ca/bootstrap:/opt/cryptic/lib/cryptic-1.0.0/priv/ca/bootstrap:rw \
  -v ~/.gnupg:/home/cryptic/.gnupg:rw \
  ghcr.io/etnt/cryptic:latest sh -c 'bootstrap-admin bob'

# Then start the server (it will read all GPG keys from priv/ca/bootstrap/)
docker run -d --name cryptic-server ...
```

## The Client

The Cryptic TUI (Terminal User Interface) client can run in Docker to
connect to a Cryptic server. This approach provides a consistent,
containerized environment for the client without requiring local
Erlang/Rust installation.

### Architecture Overview

The Docker TUI client uses the existing `bin/cryptic --tui` script,
which automatically:
1. Starts an Erlang backend node.
2. Launches the Rust TUI binary.
3. Manages lifecycle, authentication, and graceful shutdown.

```
┌─────────────────────────────────────────┐
│  Docker Container: cryptic-tui          │
│                                         │
│  bin/cryptic --tui                      │
│  ├─> Erlang Node (backend)              │
│  │   ├─ cryptic_engine                  │
│  │   ├─ cryptic_ws_client               │
│  │   └─ cryptic_tui_bridge              │
│  │                                      │
│  └─> Rust TUI (frontend)                │
│      └─ Connects via dist Erlang        │
└─────────────────────────────────────────┘
           │
           │ WebSocket mTLS (over network/internet)
           ▼
┌─────────────────────────────────────────┐
│  Cryptic Server (managed elsewhere)     │
│  (WebSocket server on port 8443)        │
└─────────────────────────────────────────┘
```

### Prerequisites

1. **Docker** (version 20.10 or later)
   ```bash
   docker --version
   ```

2. **Docker Compose** (version 2.0 or later)
   ```bash
   docker compose version
   ```

3. **User Identity Setup** - You need to set up your Cryptic identity first.
   You can run the onboarding process from within the Docker container:
   ```bash
   docker compose run --rm cryptic-tui sh -c "cryptic --onboard"
   ```
   This creates your certificates and keys in `~/.cryptic/<username>/<server>_<port>/`

4. **cryptic-tui Repository** (temporary requirement) - The Docker build
   requires the `cryptic-tui` repository to be available as a sibling directory:
   ```
   parent-directory/
   ├── cryptic/           ← This repository
   └── cryptic-tui/       ← Clone of git@github.com:etnt/cryptic-tui.git
   ```

   Clone it:
   ```bash
   cd /path/to/your/projects
   git clone git@github.com:etnt/cryptic-tui.git
   ```

   **Note**: Once `cryptic-tui` is publicly released on GitHub, the
   Dockerfile will be updated to clone it automatically, eliminating
   this manual step.

### Quick Start

1. **Ensure cryptic-tui is cloned** (see Prerequisites above):
   ```bash
   ls ../cryptic-tui/  # Should show the cryptic-tui repository
   ```

2. **Build the Docker image**:
   ```bash
   docker compose build cryptic-tui
   ```

3. **Connect to a server**:
   ```bash
   CRYPTIC_USERNAME=alice \
   CRYPTIC_SERVER_HOST=relay.example.com \
   CRYPTIC_SERVER_PORT=8443 \
   CRYPTIC_ENABLE_DB=true \
   docker compose run --rm cryptic-tui
   ```

4. **For local development** (connecting to localhost server):
   ```bash
   CRYPTIC_USERNAME=alice \
   CRYPTIC_SERVER_HOST=cryptic-server \
   CRYPTIC_ENABLE_DB=true \
   docker compose run --rm cryptic-tui
   ```

### Configuration

#### Environment Variables

Configure the client using these environment variables (mapped to `bin/cryptic` script options):

| Docker Env Variable | Script Option | Default | Description |
|---------------------|---------------|---------|-------------|
| `CRYPTIC_USERNAME` | `-u, --username` | `alice` | Your username |
| `CRYPTIC_SERVER_HOST` | `-s, --server-host` | `localhost` | Server hostname |
| `CRYPTIC_SERVER_PORT` | `-p, --server-port` | `8443` | Server port |
| `CRYPTIC_NODE_NAME` | `--name` | `localhost` | Erlang node hostname |
| `CRYPTIC_ENABLE_DB` | `--enable-db` | `false` | Enable message history |
| `CRYPTIC_DEBUG` | (internal flag) | `false` | Enable verbose debug logging |
| `ERLANG_COOKIE` | (Erlang cookie) | (auto-generated) | Erlang distributed cookie for node authentication |

**Note on Erlang Cookie**: If not provided, the entrypoint script will generate a random cookie and display it. For connecting to other Erlang nodes, you must set the same `ERLANG_COOKIE` value across all nodes.

**Example with custom settings**:


#### Volume Mounts - Critical for Persistence

The container mounts the entire `~/.cryptic` directory (read-write):

```yaml
volumes:
  - ~/.cryptic:/home/cryptic/.cryptic
```

**Note**: The `.erlang.cookie` file is NOT mounted from the host. It's automatically generated inside the container by the entrypoint script and is only used for intra-container distributed Erlang communication between the Erlang backend node and the Rust TUI process.

This directory contains **all persistent storage**:
- **Certificates**: `<username>/<server>_<port>/certificates/*.{crt,key}`
- **Identity Keys**: `<username>/<server>_<port>/keys.encrypted` (X3DH keys)
- **Session States**: `<username>/<server>_<port>/sessions/*.session` (Double Ratchet)
- **Message Database**: `<username>/messages.db` (if `--enable-db`)
- **Logs**: `logs/cryptic-tui.log.*`

**Why read-write?** The Erlang backend needs to:
- Load and save encrypted identity keys
- Update Double Ratchet session states after each message
- Write to SQLite database (if message history enabled)
- Append to log files

**Permission note**: 
- On macOS/Windows Docker Desktop, file permissions work automatically
- On Linux, ensure your user owns `~/.cryptic/` or the container's UID (100) can write to it

### Docker Image Details

#### Multi-Stage Build

The `Dockerfile.tui` uses three stages:

1. **Rust builder stage** (based on `rust:1.83-alpine`):
   - Compiles the Rust TUI binary from `../cryptic-tui/`
   - Produces a statically linked executable

2. **Erlang builder stage** (based on `erlang:28.1-alpine`):
   - Installs rebar3
   - Compiles the Erlang application
   - Builds the `cryptic_nif.so` native library with libsodium
   - Creates a production release

3. **Runtime stage** (based on `alpine:latest`):
   - Minimal base image with OpenSSL, libsodium, and ncurses
   - Non-root user (`cryptic:cryptic`)
   - Includes both Erlang release and Rust TUI binary
   - Configured for interactive terminal mode
   - Uses `docker-tui-entrypoint.sh` for initialization

The entrypoint script (`docker-tui-entrypoint.sh`) handles:
- Fixing permissions on mounted `~/.cryptic` directory
- Setting up or generating Erlang cookie (`.erlang.cookie`)
- Checking for required certificates (with helpful error messages)
- Displaying connection information
- Launching `cryptic --tui` with proper environment

#### Key Design Decisions

1. **Entrypoint script**: Uses `docker-tui-entrypoint.sh` for setup (permission fixes, Erlang cookie, certificate checks)
2. **Reuse existing launcher**: Calls `cryptic --tui` for actual TUI launch
3. **Environment over args**: Maps script flags to Docker environment variables
4. **Standard structure**: Follows same directory layout as local installation
5. **Server hostname flexibility**: Can connect to any server (local or remote)
6. **Interactive mode**: Requires `stdin_open: true` and `tty: true` for terminal UI
7. **Client-only focus**: Client doesn't need to build or manage the server
8. **User-friendly feedback**: Provides helpful error messages and connection info on startup

### Common Operations

#### Building the Image

Build the Docker image:
```bash
docker compose build cryptic-tui
```

Build without cache (fresh build):
```bash
docker compose build --no-cache cryptic-tui
```

#### Running the Client

Run interactively (recommended):
```bash
CRYPTIC_USERNAME=alice docker compose run --rm cryptic-tui
```

Run with custom server:
```bash
CRYPTIC_USERNAME=alice \
CRYPTIC_SERVER_HOST=relay.example.com \
docker compose run --rm cryptic-tui
```

Enable message history:
```bash
CRYPTIC_USERNAME=alice \
CRYPTIC_ENABLE_DB=true \
docker compose run --rm cryptic-tui
```

#### Accessing the Container

Open a shell in the container (for debugging):
```bash
docker compose run --rm cryptic-tui /bin/sh
```

Run the client manually (inside container):
```bash
docker compose run --rm cryptic-tui /bin/sh
# Inside container:
cryptic --tui -u alice -s cryptic-server -p 8443
```

Run in console mode (no TUI):
```bash
docker compose run --rm cryptic-tui cryptic -u alice -s cryptic-server
```

Run the onboarding script (no TUI):
```bash
docker compose run --rm cryptic-tui cryptic --onboard
```

**NOTE** When running the onboarding script with **--onboard** , then you
have to continue through all steps 1-3, i.e generate GPG keys (1),
export your key (2) and send it to the administrator of the server,
request a certificate (3) (when registered). Else, you will loose your
GPG key if you exit the container half-way through and you have to repeat
the process again. Not until your certificate has been received will it be
stored on your shared ~/.cryptic volume.

#### Viewing Logs

Check TUI logs (from host):
```bash
tail -f ~/.cryptic/logs/cryptic-tui.log.*
```

Inside container:
```bash
docker compose run --rm cryptic-tui /bin/sh
tail -f /home/cryptic/.cryptic/logs/cryptic-tui.log.*
```

Check cryptic client logs (from host):
```bash
tail -f ~/.cryptic/<username>/<server>_<port>/logs/cryptic-tui.log.*
```


### Networking

#### Connecting to Host Server (Development)

When the Cryptic server runs on your host machine:

```bash
CRYPTIC_SERVER_HOST=cryptic-server docker compose run --rm cryptic-tui
```

The mapping is done in `extra_hosts` in `docker-compose.yml`:
```yaml
services:
  cryptic-tui:
    extra_hosts:
      - "cryptic-server:host-gateway"
```

**NOTE** The Cryptic server has a SAN extension: _DNS: cryptic-server_ in
its certificate.

#### Connecting to Another Container

If the server runs in Docker on the same network:
```bash
CRYPTIC_SERVER_HOST=cryptic-server docker compose run --rm cryptic-tui
```

Ensure both services are on the same network:
```yaml
services:
  cryptic-server:
    networks:
      - cryptic-network

  cryptic-tui:
    networks:
      - cryptic-network

networks:
  cryptic-network:
    driver: bridge
```

#### Connecting to Remote Server

For production/remote servers:
```bash
CRYPTIC_USERNAME=alice \
CRYPTIC_SERVER_HOST=relay.example.com \
CRYPTIC_SERVER_PORT=8443 \
docker compose run --rm cryptic-tui
```

### Troubleshooting

#### Build Failures

**Error: "COPY failed: file not found in build context"**

This means `cryptic-tui` is not in the expected location.

**NOTE** FIXME - this is just temporary until the repo is public

Solution:
```bash
# Check current location
pwd
# Should be inside the cryptic directory

# Check parent directory
ls ../
# Should show cryptic-tui directory

# If not, clone it:
cd ..
git clone git@github.com:etnt/cryptic-tui.git
cd cryptic
```

**Error: "failed to compute cache key: too many links"**

This is a macOS Docker issue with symlinks (resolved in current Dockerfile).

If you still encounter it:
```bash
# Clean Docker build cache
docker builder prune -a
docker compose build --no-cache cryptic-tui
```

**Error: "error getting credentials - docker-credential-desktop not found"**

Temporary fix for macOS Docker Desktop:
```bash
# Backup config
cp ~/.docker/config.json ~/.docker/config.json.backup

# Remove problematic credsStore setting
jq 'del(.credsStore)' ~/.docker/config.json > ~/.docker/config.json.tmp
mv ~/.docker/config.json.tmp ~/.docker/config.json

# Try build again
docker compose build cryptic-tui
```

#### Connection Issues

**Cannot connect to server**

Check environment variables:
```bash
docker compose run --rm cryptic-tui env | grep CRYPTIC
```

Verify server is reachable from container:
```bash
docker compose run --rm cryptic-tui ping cryptic-server
# or
docker compose run --rm cryptic-tui nc -zv cryptic-server 8443
```

**TUI starts but connection fails**

Check certificates exist:
```bash
ls -la ~/.cryptic/alice/localhost_8443/certificates/
# Should show: alice.crt, alice.key, ca.crt
```

If certificates are missing, the entrypoint script will display a warning with instructions. Run onboarding:
```bash
docker compose run --rm cryptic-tui sh -c "cryptic --onboard"
```

Verify server host setting:
```bash
docker compose run --rm cryptic-tui env | grep CRYPTIC_SERVER_HOST
```

**Debug mode**

Enable verbose logging:
```bash
CRYPTIC_DEBUG=true docker compose run --rm cryptic-tui
# Then check logs:
tail -f ~/.cryptic/logs/cryptic-tui.log.*
```

#### Terminal Display Issues

**Terminal size incorrect**

Ensure TTY is enabled:
```yaml
services:
  cryptic-tui:
    stdin_open: true
    tty: true
```

**Colors not working**

Set terminal type:
```bash
TERM=xterm-256color docker compose run --rm cryptic-tui
```

**TUI not responding to input**

Check if stdin is properly attached:
```bash
# Use -it flags explicitly
docker compose run -it --rm cryptic-tui
```

#### Permission Issues (Linux)

If you get permission errors on `~/.cryptic/`:

```bash
# Check ownership
ls -ld ~/.cryptic

# Fix ownership (replace 1000:1000 with your UID:GID)
sudo chown -R 1000:1000 ~/.cryptic

# Or set permissions
chmod -R u+rwX ~/.cryptic
```

### Production Deployment

#### Security Considerations

1. **Certificate management**: Ensure certificates are properly protected
2. **Volume permissions**: Set strict permissions on `~/.cryptic/` (0700)
3. **Network isolation**: Use Docker networks to isolate client traffic
4. **Regular updates**: Keep the base image and dependencies updated
5. **Debug logging**: Disable `CRYPTIC_DEBUG` in production

#### Recommended Setup

1. **Use secrets for sensitive data**:
   ```yaml
   services:
     cryptic-tui:
       secrets:
         - user_cert
         - user_key

   secrets:
     user_cert:
       file: ~/.cryptic/alice/localhost_8443/certificates/alice.crt
     user_key:
       file: ~/.cryptic/alice/localhost_8443/certificates/alice.key
   ```

2. **Set resource limits**:
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

3. **Use specific image tags**:
   ```yaml
   services:
     cryptic-tui:
       image: cryptic-tui:1.0.0  # Don't use :latest in production
   ```

### Advanced Usage

#### Running Without Docker Compose

Run the container directly:

```bash
docker run -it --rm \
  --name cryptic-tui \
  -v ~/.cryptic:/home/cryptic/.cryptic \
  -e CRYPTIC_USERNAME=alice \
  -e CRYPTIC_SERVER_HOST=relay.example.com \
  -e CRYPTIC_SERVER_PORT=8443 \
  -e CRYPTIC_ENABLE_DB=false \
  cryptic-tui
```

#### Building for Different Architectures

Build for ARM64 (Apple Silicon):
```bash
docker buildx build -f Dockerfile.tui --platform linux/arm64 -t cryptic-tui:arm64 .
```

Build multi-architecture image:
```bash
docker buildx build -f Dockerfile.tui --platform linux/amd64,linux/arm64 -t cryptic-tui:latest .
```

#### Custom Build with Local cryptic-tui Changes

If you're developing `cryptic-tui`:

```bash
# Make changes to ../cryptic-tui/
# Then rebuild:
docker compose build --no-cache cryptic-tui

# Test your changes:
CRYPTIC_USERNAME=alice docker compose run --rm cryptic-tui
```

### Future Improvements

Once the `cryptic-tui` repository is public, the Dockerfile will be updated to:

```dockerfile
# Future version (no manual clone needed)
RUN git clone https://github.com/etnt/cryptic-tui.git /cryptic-tui
```

This will eliminate the need for manual cloning and sibling directory setup.

## The Server

The Cryptic server Docker deployment uses a multi-stage build process to create
a minimal, secure container image. The image runs the Erlang release in
foreground mode and requires external mTLS certificates mounted as volumes.

### Prerequisites

1. **Docker** (version 20.10 or later)
   ```bash
   docker --version
   ```

2. **Docker Compose** (version 2.0 or later)
   ```bash
   docker compose version
   ```

3. **mTLS Certificates** - You need:
   - Server certificate (`server.crt`)
   - Server private key (`server.key`)
   - CA certificate (`ca.crt`)

   See [Certificate Generation](#certificate-generation) below for instructions.

### Quick Start

1. **Generate certificates** (if you haven't already):
   ```bash
   ./scripts/generate-mtls-certs.sh
   ```

2. **Build the Docker image**:
   ```bash
   docker build -t cryptic-server .
   ```

3. **Start the server** using Docker Compose:
   ```bash
   docker compose up -d
   ```

4. **Check server status**:
   ```bash
   docker compose ps
   docker compose logs -f cryptic-server
   ```

5. **Connect a client** (from the host):
   ```bash
   cryptic_console ...
   ```

6. **Study the server.log**:
   ```bash
   # Tail the log in real-time 
   docker exec cryptic-server tail -f /opt/cryptic/logs/server.log

   # Copy the log to your host 
   docker cp cryptic-server:/opt/cryptic/logs/server.log ./server.log

   # Interactive shell 
   docker exec -it cryptic-server /bin/sh
   # Then you can use: cd /opt/cryptic/logs && ls -la
   # And: cat server.log, tail -f server.log, etc.
   ```

7. **Get a remote Erlang shell**:
```bash
   docker exec -it cryptic-server bin/cryptic remote_console
```

### Docker Image Details

#### Multi-Stage Build

The Dockerfile uses two stages:

1. **Builder stage** (based on `erlang:28.1-alpine`):
   - Installs rebar3
   - Compiles the Erlang application
   - Builds the cryptic_nif.so native library with libsodium
   - Creates a production release

2. **Runtime stage** (based on `alpine:latest`):
   - Minimal base image with OpenSSL and libsodium
   - Non-root user (`cryptic:cryptic`)
   - Only includes the compiled release
   - Health check on port 8443

#### Image Size

The final image is approximately **38-40 MB**, significantly smaller than
including the full Erlang/OTP development environment.

### Configuration

#### Environment Variables

Configure the server using these environment variables (names reflect the Erlang server code in `cryptic_server.erl` and `cryptic_ca_app.erl`):

| Variable                | Default                                   | Description |
|-------------------------|-------------------------------------------|-------------|
| `CRYPTIC_SERVER_HOST`   | `0.0.0.0`                                 | Server bind address (use 0.0.0.0 for Docker) |
| `CRYPTIC_SERVER_PORT`   | `8443`                                    | WebSocket server port |
| `CRYPTIC_SERVER_CERT`   | `/opt/cryptic/certs/server.crt`           | Server certificate path (mTLS) |
| `CRYPTIC_SERVER_KEY`    | `/opt/cryptic/certs/server.key`           | Server private key path |
| `CRYPTIC_CA_CERT`       | `/opt/cryptic/certs/ca.crt`               | CA certificate used to verify client certs |
| `CRYPTIC_CA_DB_FILE`    | `/opt/cryptic/data/ca/cryptic_ca.db`      | CA database (stores user registrations, fingerprints, issuance metadata) |
| `CRYPTIC_EVENT_HANDLERS`| `cryptic_file_logger`                     | Comma-separated event handlers (logging) |
| `CRYPTIC_DEBUG`         | (unset)                                   | Set to `"true"` to enable verbose debug logging in event handlers |

You can override these in `docker-compose.yml`:

```yaml
services:
  cryptic-server:
    environment:
      - CRYPTIC_SERVER_PORT=9443
      - CRYPTIC_SERVER_HOST=0.0.0.0
      - CRYPTIC_DEBUG=true
```

#### Volume Mounts

The docker-compose.yml defines several volumes:

1. **Certificate volumes** (read-only):
   ```yaml
   volumes:
     - ./priv/ssl/server.crt:/opt/cryptic/certs/server.crt:ro
     - ./priv/ssl/server.key:/opt/cryptic/certs/server.key:ro
     - ./priv/ssl/ca.crt:/opt/cryptic/certs/ca.crt:ro
   ```

2. **Data volumes** (persistent):
   ```yaml
   volumes:
     - cryptic-logs:/opt/cryptic/logs
     - cryptic-data:/opt/cryptic/data
   ```

3. **Optional CA bootstrap (GPG fingerprints)**:
   If you want to preload verified user fingerprints, place `.gpg` files in `priv/ca/bootstrap/` **before building the image**, or mount a host directory into the release `priv` path after deployment.
   During build, the release copies your `priv/` tree, so any files under `priv/ca/bootstrap` become available at runtime.

   Example (build-time approach):
   ```bash
   # Add files like priv/ca/bootstrap/alice.gpg, bob.gpg
   docker build -t cryptic-server .
   ```

   Example (runtime mount — adjust version number after inspecting container):
   ```bash
   # Discover priv dir inside container
   docker compose exec cryptic-server bin/cryptic eval 'io:format("~s\n", [code:priv_dir(cryptic)]).'
   # Suppose output is /opt/cryptic/lib/cryptic-1.2.3/priv
   # Then add to docker-compose.yml:
   volumes:
     - ./bootstrap:/opt/cryptic/lib/cryptic-1.2.3/priv/ca/bootstrap:ro
   ```

#### Port Mapping

The default configuration maps port 8443 from the container to the host:

```yaml
ports:
  - "8443:8443"
```

To use a different host port (e.g., 9443):

```yaml
ports:
  - "9443:8443"
```

### Certificate & CA Database Generation

Generate the CA and Server certificates using the
`scripts/generate-mtls-certs.sh` script.

**Production Note**: For production deployments, use certificates from a
trusted Certificate Authority. The CA database (`CRYPTIC_CA_DB_FILE`) is persisted on a volume; back it up regularly.

#### CA Database Persistence

The CA subsystem stores state (user registrations, issued cert metadata) in the SQLite file referenced by `CRYPTIC_CA_DB_FILE`. Mount the parent directory (`/opt/cryptic/data/ca`) as a named volume or host bind to retain state across container restarts:

```yaml
volumes:
  - cryptic-ca-data:/opt/cryptic/data/ca
```

The server does **not** store end-to-end encrypted chat messages; those are only persisted client-side in each user's `messages.db`. This keeps the server largely stateless apart from CA data and logs.

### Common Operations

#### Building the Image

Build the Docker image:
```bash
docker build -t cryptic-server .
```

Build with a specific tag:
```bash
docker build -t cryptic-server:1.0.0 .
```

#### Starting the Server

Start in detached mode:
```bash
docker compose up -d
```

Start with logs visible:
```bash
docker compose up
```

#### Stopping the Server

Stop the container:
```bash
docker compose down
```

Stop and remove volumes (careful - this deletes data!):
```bash
docker compose down -v
```

#### Viewing Logs

Follow logs in real-time:
```bash
docker compose logs -f cryptic-server
```

View last 100 lines:
```bash
docker compose logs --tail=100 cryptic-server
```

#### Accessing the Container

Open a shell in the running container:
```bash
docker compose exec cryptic-server /bin/sh
```

Attach to the Erlang console:
```bash
docker compose exec cryptic-server bin/cryptic remote_console
```

#### Health Check

The container includes a health check that verifies the server is listening on port 8443:

```bash
# Check health status
docker inspect --format='{{.State.Health.Status}}' cryptic-server

# View health check logs
docker inspect --format='{{range .State.Health.Log}}{{.Output}}{{end}}' cryptic-server
```

### Networking

#### Default Configuration

The docker-compose.yml creates a bridge network named `cryptic-network`:

```yaml
networks:
  cryptic-network:
    driver: bridge
```

#### Connecting from Host

If you're running the client on the host machine, connect to `localhost:8443`:

```bash
cryptic_console ...
# In the Cryptic shell, connect to localhost:8443
```

#### Connecting from Another Container

Add your client container to the same network:

```yaml
services:
  my-client:
    networks:
      - cryptic-network
```

Then connect to `cryptic-server:8443` (use the service name as hostname).

### Troubleshooting

#### Container Won't Start

**Check logs**:
```bash
docker compose logs cryptic-server
```

**Common issues**:
1. **Certificate files not found**: Ensure certificate paths in docker-compose.yml are correct
2. **Port already in use**: Change the host port mapping in docker-compose.yml
3. **Permission denied**: Ensure certificate files are readable
4. **NIF loading errors**: The cryptic_nif.so library requires libsodium - this is included in the image

#### Connection Refused

**Verify server is listening**:
```bash
docker compose exec cryptic-server netstat -tlnp | grep 8443
```

**Check firewall rules**:
```bash
# On the host
sudo iptables -L | grep 8443
```

**Verify CRYPTIC_SERVER_HOST**:
```bash
docker compose exec cryptic-server env | grep CRYPTIC_SERVER_HOST
# Should show: CRYPTIC_SERVER_HOST=0.0.0.0
```

#### mTLS Handshake Failures

**Verify certificates**:
```bash
# Check server certificate
openssl x509 -in priv/ssl/server.crt -text -noout

# Verify certificate chain
openssl verify -CAfile priv/ssl/ca.crt priv/ssl/server.crt
```

**Check client certificate**:
```bash
# Ensure client has valid certificate signed by same CA
openssl verify -CAfile priv/ssl/ca.crt ~/.cryptic/<username>/<server>_<port>/certificates/<username>.crt
```

#### Performance Issues

**Monitor container resources**:
```bash
docker stats cryptic-server
```

**Increase container limits** in docker-compose.yml:
```yaml
services:
  cryptic-server:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          cpus: '1.0'
          memory: 512M
```

### Production Deployment

#### Security Considerations

1. **Use proper certificates**: Don't use self-signed certificates in production
2. **Secure private keys**: Set strict permissions (0400) on key files
3. **Run as non-root**: The container runs as user `cryptic` (UID 1000)
4. **Network isolation**: Use Docker networks to isolate the server
5. **Regular updates**: Keep the base image and dependencies updated

#### Recommended Setup

1. **Use Docker secrets** for sensitive data:
   ```yaml
   services:
     cryptic-server:
       secrets:
         - server_key
         - server_cert
         - ca_cert

   secrets:
     server_key:
       file: ./priv/ssl/server.key
     server_cert:
       file: ./priv/ssl/server.crt
     ca_cert:
       file: ./priv/ssl/ca.crt
```

3. **Use health checks** with orchestration (Kubernetes, Swarm):
   ```yaml
   healthcheck:
     test: ["CMD", "nc", "-z", "localhost", "8443"]
     interval: 30s
     timeout: 10s
     retries: 3
     start_period: 40s
   ```

4. **Set resource limits**:
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '2'
         memory: 2G
   ```

### Advanced Usage

#### Building for Different Architectures

Build for ARM64 (e.g., Apple Silicon):
```bash
docker buildx build --platform linux/arm64 -t cryptic-server:arm64 .
```

Build multi-architecture image:
```bash
docker buildx build --platform linux/amd64,linux/arm64 -t cryptic-server:latest .
```

#### Custom Build Args

The Dockerfile is configured for Erlang 28.1 and Alpine Linux.
The build process includes:
- Erlang/OTP 28.1 for the build stage
- Alpine Linux (latest) for the runtime stage
- libsodium for cryptographic operations
- Explicit ARM64 architecture support for Apple Silicon

Build with specific settings:

```bash
docker build -t cryptic-server .
```

#### Running Without Docker Compose

Run the container directly:

```bash
docker run -d \
  --name cryptic-server \
  -p 8443:8443 \
  -v $(pwd)/priv/ssl/server.crt:/opt/cryptic/certs/server.crt:ro \
  -v $(pwd)/priv/ssl/server.key:/opt/cryptic/certs/server.key:ro \
  -v $(pwd)/priv/ssl/ca.crt:/opt/cryptic/certs/ca.crt:ro \
  -v cryptic-logs:/opt/cryptic/logs \
  -v cryptic-data:/opt/cryptic/data \
  -e CRYPTIC_SERVER_HOST=0.0.0.0 \
  -e CRYPTIC_SERVER_PORT=8443 \
  -e CRYPTIC_CA_DB_FILE=/opt/cryptic/data/ca/cryptic_ca.db \
  -e CRYPTIC_DEBUG=true \
  --restart unless-stopped \
  cryptic-server
```

### Integration with CI/CD

Example GitHub Actions workflow:

```yaml
name: Build Docker Image

on:
  push:
    branches: [ main ]
    tags: [ 'v*' ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          context: .
          push: false
          tags: cryptic-server:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

---

## References

- [Erlang Docker Example](https://github.com/erlang/docker-erlang-example)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Cowboy WebSocket Documentation](https://ninenines.eu/docs/en/cowboy/2.9/guide/ws_handlers/)

## Support

For issues or questions:
- Check the [main README](../README.md)
- Review the [logs](#viewing-logs)
- Open an issue on GitHub
