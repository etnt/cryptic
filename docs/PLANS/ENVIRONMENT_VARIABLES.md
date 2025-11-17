# Cryptic Environment Variables Configuration

## Server Certificates

Set these environment variables to specify certificate paths:

```bash
export CRYPTIC_SERVER_CERT="CA/certs/server.crt"
export CRYPTIC_SERVER_KEY="CA/private/server.key"
export CRYPTIC_CA_CERT="CA/certs/ca.crt"
```

## Client Certificates

Set these environment variables to specify client certificate paths:

```bash
export CRYPTIC_CLIENT_CERT="CA/client_keys/alice.crt"
export CRYPTIC_CLIENT_KEY="CA/client_keys/alice.key"
export CRYPTIC_CA_CERT="CA/certs/ca.crt"
```

## Event Handlers / Logging Configuration

Configure logging using the `CRYPTIC_EVENT_HANDLERS` environment variable:

### Console Logging Only (Default)
```bash
export CRYPTIC_EVENT_HANDLERS="cryptic_console_logger"
./scripts/start-server.sh
```

### File Logging Only
```bash
export CRYPTIC_EVENT_HANDLERS="cryptic_file_logger"
./scripts/start-server.sh
```
Logs will be written to:
- `logs/server.log` for server events
- `logs/client.log` for client events

### Both Console and File Logging
```bash
export CRYPTIC_EVENT_HANDLERS="cryptic_console_logger,cryptic_file_logger"
./scripts/start-server.sh
```

### No Logging
```bash
export CRYPTIC_EVENT_HANDLERS=""
./scripts/start-server.sh
```

## Usage Examples

### Start Server with File Logging
```bash
export CRYPTIC_SERVER_CERT="CA/certs/server.crt"
export CRYPTIC_SERVER_KEY="CA/private/server.key"
export CRYPTIC_CA_CERT="CA/certs/ca.crt"
export CRYPTIC_EVENT_HANDLERS="cryptic_file_logger"
./scripts/start-server.sh
```

### Start Client with Environment Variables
```bash
export CRYPTIC_CLIENT_CERT="CA/client_keys/alice.crt"
export CRYPTIC_CLIENT_KEY="CA/client_keys/alice.key"
export CRYPTIC_CA_CERT="CA/certs/ca.crt"
export CRYPTIC_EVENT_HANDLERS="cryptic_file_logger"
./scripts/start-client.sh alice
```

### Development Setup (Both Console and File Logging)
```bash
# Server terminal
export CRYPTIC_EVENT_HANDLERS="cryptic_console_logger,cryptic_file_logger"
./scripts/start-server.sh

# Client terminal
export CRYPTIC_EVENT_HANDLERS="cryptic_file_logger"  # Keep client logs in files only
./scripts/start-client.sh alice
```

## Quick Start Scripts

The provided scripts have sensible defaults:

- `./scripts/start-server.sh` - Uses file logging by default
- `./scripts/start-client.sh [username]` - Uses default client certificates for the specified user
