# Quick Start: Running Cryptic TUI Client in Docker

This guide shows you how to run the Cryptic TUI client in Docker to connect to a Cryptic server.

## Prerequisites

- Docker and Docker Compose installed
- GPG installed (`gpg --version`)
- Terminal access
- **Access to a running Cryptic server** (managed by someone else, or see note below)
- **cryptic-tui repository** cloned as a sibling directory (temporary requirement)

> **Note for Testing**: If you need to run a local server for development/testing purposes, see the separate server documentation. This guide assumes you're connecting to an existing server.

> **Note about cryptic-tui**: The Rust TUI application is currently in a separate repository. Until it's publicly released, you need to clone it locally:
> ```bash
> cd /path/to/your/projects
> git clone git@github.com:etnt/cryptic-tui.git  # Use SSH if you have access
> git clone <path-to-cryptic>                     # Clone or locate cryptic repo
> # Directory structure should be:
> # projects/
> #   ├── cryptic/           (this repo)
> #   └── cryptic-tui/       (TUI repo - sibling directory)
> ```

## Step 1: Get Server Connection Details

You'll need from your server administrator:
- Server hostname/IP (e.g., `relay.example.com` or `cryptic-server`)
- Server port (typically `8443`)
- CA certificate (to verify server identity)

## Step 2: Set Up Your Client Identity

**Use the cryptic-onboard tool** (recommended):

```bash
bin/cryptic-onboard
```

This interactive wizard will:
1. Check/generate your GPG key
2. Export your public key for admin registration
3. Wait for you to confirm admin registration
4. Request a certificate from the server

When prompted for the server URL, use the server address provided by your administrator (e.g., `https://relay.example.com:8443`).

**Or use the automated setup script**:

```bash
scripts/setup-docker-tui.sh
```

This script wraps `cryptic-onboard` with additional Docker-specific checks.

### Important: Admin Registration Step

During the onboarding process, you'll see your GPG fingerprint displayed. **Send this fingerprint to your server administrator** - they need to register it before you can get a certificate.

Wait for confirmation from the admin that your fingerprint has been registered, then continue the setup process.

## Step 3: Build the TUI Client Image

```bash
docker-compose build cryptic-tui
```

This will:
- Compile the Rust TUI binary
- Build the Erlang application
- Create a runtime image with both

## Step 4: Run the TUI Client

### Option A: Using the helper script (easiest)

```bash
scripts/run-tui.sh alice
```

### Option B: Using docker-compose directly

```bash
TUI_USERNAME=alice docker-compose run --rm cryptic-tui
```

### Option C: Connect to a custom server

```bash
TUI_USERNAME=alice \
CRYPTIC_SERVER_HOST=relay.example.com \
CRYPTIC_SERVER_PORT=8443 \
docker-compose run --rm cryptic-tui
```

### Option D: With message history enabled

```bash
TUI_USERNAME=alice CRYPTIC_ENABLE_DB=true docker-compose run --rm cryptic-tui
```

## Step 5: Test the TUI

Once the TUI starts, you should see:
- A chat interface with tabs
- Connection status in the header
- User list on the left

**Keyboard shortcuts**:
- `Ctrl+Q` - Quit
- `Tab` - Switch tabs
- `Enter` - Send message
- `↑/↓` - Navigate user list

## Step 6: Test with Multiple Users

Open multiple terminals and run different users:

```bash
# Terminal 1
scripts/run-tui.sh alice

# Terminal 2  
scripts/run-tui.sh bob

# Terminal 3
scripts/run-tui.sh charlie
```

**Note**: Each user needs their own GPG key and certificate setup.

## Troubleshooting

### Docker build fails with "cryptic-tui: no such file or directory"

The build requires the `cryptic-tui` repository as a sibling directory:

```bash
# Check your directory structure
ls -la ../ | grep cryptic

# Should show:
# cryptic/
# cryptic-tui/

# If cryptic-tui is missing, clone it:
cd ..
git clone git@github.com:etnt/cryptic-tui.git
cd cryptic
```

### "Cannot connect to server"

```bash
# Test connectivity from container
docker-compose run --rm cryptic-tui ping <server-hostname>

# Verify DNS resolution
docker-compose run --rm cryptic-tui nslookup <server-hostname>

# Check if server port is open
docker-compose run --rm cryptic-tui nc -zv <server-hostname> 8443
```

Contact your server administrator if the server appears unreachable.

### "Certificate not found"

```bash
# Verify certificate files exist
ls -la ~/.cryptic/alice/<servername>_<port>/certificates/

# Should contain:
# - alice.crt
# - alice.key  
# - ca.crt

# If missing, re-run:
bin/cryptic-onboard
```

The certificate path must match your server's hostname. For example, if connecting to `relay.example.com:8443`, you should have:
```
~/.cryptic/alice/relay.example.com_8443/certificates/
```

### "Permission denied on ~/.cryptic"

```bash
# Fix permissions
chmod -R u+rwX ~/.cryptic/

# Check directory is accessible
ls -la ~/.cryptic/
```

### "GPG key not registered"

The server administrator must register your GPG fingerprint before you can get a certificate.

```bash
# Find your fingerprint
gpg --list-secret-keys --keyid-format LONG

# Send this fingerprint to your server administrator
```

Contact your server administrator to have your fingerprint registered.

## Clean Up

## Clean Up

### Stop TUI client
```bash
# Press Ctrl+Q in the TUI, or Ctrl+C from terminal
```

### Remove client data
```bash
# CAREFUL: This deletes all your keys and messages!
rm -rf ~/.cryptic/
```

### Remove image
```bash
docker rmi cryptic-tui:latest
```

## Quick Reference

```bash
# Build client image
docker-compose build cryptic-tui

# Setup client (first time)
scripts/setup-docker-tui.sh

# Run TUI
scripts/run-tui.sh alice

# Connect to custom server
TUI_USERNAME=alice \
CRYPTIC_SERVER_HOST=relay.example.com \
CRYPTIC_SERVER_PORT=8443 \
docker-compose run --rm cryptic-tui
```

## For Local Testing Only
```bash
# CAREFUL: This deletes all your keys and messages!
rm -rf ~/.cryptic/
## For Local Testing Only

If you need to run a local server for development/testing (not typical for end users):

```bash
# Build and start local server
docker-compose build cryptic-server
docker-compose up -d cryptic-server

# Generate server certificates (if needed)
make certs

# Check server is running
docker-compose ps
docker-compose logs cryptic-server

# Connect to local server
TUI_USERNAME=alice \
CRYPTIC_SERVER_HOST=cryptic-server \
docker-compose run --rm cryptic-tui
```

For local testing, you can simulate admin registration by adding your GPG fingerprint to `priv/ca/bootstrap/approved_fingerprints.txt` before starting the server.

## Next Steps

- Read [DOCKER-TUI-SIMPLE.md](docs/DOCKER-TUI-SIMPLE.md) for detailed usage
- Check [AGENTS.md](AGENTS.md) for architecture details
- See [cryptic-tui/README.md](cryptic-tui/README.md) for TUI features

## Quick Reference

```bash
# Build
docker-compose build

# Start server
docker-compose up -d cryptic-server

# Setup client (first time)
scripts/setup-docker-tui.sh

# Run TUI
scripts/run-tui.sh alice

# View logs
docker-compose logs -f cryptic-tui

# Stop everything
docker-compose down
```

## Development Tips

### Rebuild after code changes

```bash
# Rebuild TUI client
docker-compose build cryptic-tui
```

### View container filesystem

```bash
# Explore TUI container
docker-compose run --rm cryptic-tui /bin/bash

# Inside container:
ls -la /opt/cryptic/
ls -la /home/cryptic/.cryptic/
```

### Debug Erlang backend

```bash
# Run TUI with bash shell
docker-compose run --rm cryptic-tui /bin/bash

# Inside container:
cd /opt/cryptic
bin/cryptic --tui  # Run manually
# or
erl -pa _build/default/lib/*/ebin  # Start Erlang shell
```

### Check what's mounted

```bash
docker-compose run --rm cryptic-tui sh -c "mount | grep cryptic"
```

## Common Workflows

### Add a new user

```bash
# 1. Generate GPG key (if needed)
gpg --full-generate-key

# 2. Run onboarding for the new user
bin/cryptic-onboard

# 3. Send your GPG fingerprint to server admin
# (Wait for admin confirmation)

# 4. Run TUI
scripts/run-tui.sh newuser
```

### Reset a user's data

```bash
# Remove user's directory
rm -rf ~/.cryptic/alice/

# Re-run setup
scripts/setup-docker-tui.sh
```

Happy chatting! 🚀
