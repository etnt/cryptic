# Cryptic MCP Admin Server

An [MCP](https://modelcontextprotocol.io/) server that exposes Cryptic messaging server administration tools to AI assistants (Claude Desktop, VS Code Copilot, etc.).

## Prerequisites

- Python 3.10+
- A running Cryptic server with the MCP TCP endpoint enabled
- An admin GPG fingerprint (bootstrap admin)

## Setup

```bash
cd mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Or with `uv`:

```bash
cd mcp
uv venv .venv
source .venv/bin/activate
uv pip install -e .
```

## Configuration

Set the following environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `CRYPTIC_ADMIN_GPG_FP` | **Yes** | — | Your admin GPG fingerprint |
| `CRYPTIC_MCP_BASE_URL` | No | `http://127.0.0.1:8081/mcp/v1/admin` | Base URL of the Cryptic admin API |

### Enable the MCP endpoint on the Cryptic server

In your Erlang `sys.config` or via environment:

```erlang
{cryptic, [
    {mcp_tcp_enabled, true},
    {mcp_tcp_port, 8081}   % default
]}.
```

Or set `CRYPTIC_MCP_PORT=8081` environment variable.

## Usage with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cryptic-admin": {
      "command": "/path/to/cryptic/mcp/.venv/bin/python",
      "args": ["/path/to/cryptic/mcp/cryptic_mcp_server.py"],
      "env": {
        "CRYPTIC_ADMIN_GPG_FP": "YOUR_ADMIN_GPG_FINGERPRINT"
      }
    }
  }
}
```

## Usage with VS Code / GitHub Copilot

Add to your `.vscode/mcp.json`:

```json
{
  "servers": {
    "cryptic-admin": {
      "type": "stdio",
      "command": "${workspaceFolder}/mcp/.venv/bin/python",
      "args": ["${workspaceFolder}/mcp/cryptic_mcp_server.py"],
      "env": {
        "CRYPTIC_ADMIN_GPG_FP": "YOUR_ADMIN_GPG_FINGERPRINT"
      }
    }
  }
}
```

## Available Tools

### Read-only

| Tool | Description |
|------|-------------|
| `server_status` | Server overview (listener, ETS tables, CA state) |
| `list_users` | List registered users with optional status filter |
| `get_user_info` | Detailed info for a user by GPG fingerprint |
| `list_online_users` | Currently connected users |
| `list_connections` | WebSocket connection details with process stats |
| `list_pending_messages` | Pending offline message summary (or per-user) |
| `list_key_bundles` | X3DH key bundle summary (or per-user details) |
| `list_certificates` | TLS certificates for a user |
| `get_audit_log` | Recent audit log entries |
| `list_enrollments` | List mobile enrollment identities |
| `get_enrollment_info` | Detailed info for a mobile enrollment |

### Write

| Tool | Description |
|------|-------------|
| `register_user` | Register a new user with GPG key |
| `suspend_user` | Suspend a user |
| `reactivate_user` | Reactivate a suspended user |
| `revoke_user` | Permanently revoke a user |
| `revoke_certificate` | Revoke a TLS certificate |
| `register_enrollment` | Register a new mobile enrollment identity |
| `suspend_enrollment` | Suspend a mobile enrollment |
| `reactivate_enrollment` | Reactivate a suspended enrollment |
| `revoke_enrollment` | Permanently revoke a mobile enrollment |
| `delete_enrollment` | Delete enrollment completely (for debugging) |

## REST API Endpoints

The MCP server communicates with these Erlang REST endpoints (all on `127.0.0.1:8081`):

```
GET  /mcp/v1/admin/status
GET  /mcp/v1/admin/list_users?filter=active|suspended|revoked
GET  /mcp/v1/admin/user/:gpg_fp
GET  /mcp/v1/admin/user/:gpg_fp/certificates
GET  /mcp/v1/admin/online
GET  /mcp/v1/admin/connections
GET  /mcp/v1/admin/pending
GET  /mcp/v1/admin/pending/:user
GET  /mcp/v1/admin/keys
GET  /mcp/v1/admin/keys/:user
GET  /mcp/v1/admin/audit?limit=20
GET  /mcp/v1/admin/enrollments?filter=active|consumed|suspended|revoked
GET  /mcp/v1/admin/enrollment/:enrollment_fp
POST /mcp/v1/admin/register_user
POST /mcp/v1/admin/suspend_user
POST /mcp/v1/admin/revoke_user
POST /mcp/v1/admin/reactivate_user
POST /mcp/v1/admin/revoke_certificate
POST /mcp/v1/admin/register_enrollment
POST /mcp/v1/admin/suspend_enrollment
POST /mcp/v1/admin/revoke_enrollment
POST /mcp/v1/admin/reactivate_enrollment
POST /mcp/v1/admin/delete_enrollment
```

All requests require the `X-Admin-GPG-FP` header set to a bootstrap admin fingerprint.
