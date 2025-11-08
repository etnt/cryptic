# Docker Deployment Guide

This guide explains how to deploy the Cryptic server using Docker and Docker Compose.

## Overview

The Cryptic server Docker deployment uses a multi-stage build process to create
a minimal, secure container image. The image runs the Erlang release in
foreground mode and requires external mTLS certificates mounted as volumes.

## Prerequisites

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

## Quick Start

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

## Docker Image Details

### Multi-Stage Build

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

### Image Size

The final image is approximately **38-40 MB**, significantly smaller than
including the full Erlang/OTP development environment.

## Configuration

### Environment Variables

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

### Volume Mounts

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

### Port Mapping

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

## Certificate & CA Database Generation

Generate the CA and Server certificates using the
`scripts/generate-mtls-certs.sh` script.

**Production Note**: For production deployments, use certificates from a
trusted Certificate Authority. The CA database (`CRYPTIC_CA_DB_FILE`) is persisted on a volume; back it up regularly.

### CA Database Persistence

The CA subsystem stores state (user registrations, issued cert metadata) in the SQLite file referenced by `CRYPTIC_CA_DB_FILE`. Mount the parent directory (`/opt/cryptic/data/ca`) as a named volume or host bind to retain state across container restarts:

```yaml
volumes:
  - cryptic-ca-data:/opt/cryptic/data/ca
```

The server does **not** store end-to-end encrypted chat messages; those are only persisted client-side in each user's `messages.db`. This keeps the server largely stateless apart from CA data and logs.

## Common Operations

### Building the Image

Build the Docker image:
```bash
docker build -t cryptic-server .
```

Build with a specific tag:
```bash
docker build -t cryptic-server:1.0.0 .
```

### Starting the Server

Start in detached mode:
```bash
docker compose up -d
```

Start with logs visible:
```bash
docker compose up
```

### Stopping the Server

Stop the container:
```bash
docker compose down
```

Stop and remove volumes (careful - this deletes data!):
```bash
docker compose down -v
```

### Viewing Logs

Follow logs in real-time:
```bash
docker compose logs -f cryptic-server
```

View last 100 lines:
```bash
docker compose logs --tail=100 cryptic-server
```

### Accessing the Container

Open a shell in the running container:
```bash
docker compose exec cryptic-server /bin/sh
```

Attach to the Erlang console:
```bash
docker compose exec cryptic-server bin/cryptic remote_console
```

### Health Check

The container includes a health check that verifies the server is listening on port 8443:

```bash
# Check health status
docker inspect --format='{{.State.Health.Status}}' cryptic-server

# View health check logs
docker inspect --format='{{range .State.Health.Log}}{{.Output}}{{end}}' cryptic-server
```

## Networking

### Default Configuration

The docker-compose.yml creates a bridge network named `cryptic-network`:

```yaml
networks:
  cryptic-network:
    driver: bridge
```

### Connecting from Host

If you're running the client on the host machine, connect to `localhost:8443`:

```bash
cryptic_console ...
# In the Cryptic shell, connect to localhost:8443
```

### Connecting from Another Container

Add your client container to the same network:

```yaml
services:
  my-client:
    networks:
      - cryptic-network
```

Then connect to `cryptic-server:8443` (use the service name as hostname).

## Troubleshooting

### Container Won't Start

**Check logs**:
```bash
docker compose logs cryptic-server
```

**Common issues**:
1. **Certificate files not found**: Ensure certificate paths in docker-compose.yml are correct
2. **Port already in use**: Change the host port mapping in docker-compose.yml
3. **Permission denied**: Ensure certificate files are readable
4. **NIF loading errors**: The cryptic_nif.so library requires libsodium - this is included in the image

### Connection Refused

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

### mTLS Handshake Failures

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

### Performance Issues

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

## Production Deployment

### Security Considerations

1. **Use proper certificates**: Don't use self-signed certificates in production
2. **Secure private keys**: Set strict permissions (0400) on key files
3. **Run as non-root**: The container runs as user `cryptic` (UID 1000)
4. **Network isolation**: Use Docker networks to isolate the server
5. **Regular updates**: Keep the base image and dependencies updated

### Recommended Setup

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
```2. **Enable logging** to external system (e.g., Loki, ELK):
   ```yaml
   services:
     cryptic-server:
       logging:
         driver: "json-file"
         options:
           max-size: "10m"
           max-file: "3"
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

## Advanced Usage

### Building for Different Architectures

Build for ARM64 (e.g., Apple Silicon):
```bash
docker buildx build --platform linux/arm64 -t cryptic-server:arm64 .
```

Build multi-architecture image:
```bash
docker buildx build --platform linux/amd64,linux/arm64 -t cryptic-server:latest .
```

### Custom Build Args

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

### Running Without Docker Compose

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

## Integration with CI/CD

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

## References

- [Erlang Docker Example](https://github.com/erlang/docker-erlang-example)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Cowboy WebSocket Documentation](https://ninenines.eu/docs/en/cowboy/2.9/guide/ws_handlers/)

## Support

For issues or questions:
- Check the [main README](../README.md)
- Review the [logs](#viewing-logs)
- Open an issue on GitHub
