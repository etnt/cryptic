"""Cryptic MCP Admin Server.

Exposes Cryptic server administration tools via the Model Context Protocol (MCP).
Communicates with the Erlang-side REST API on localhost.
"""

import os
import sys
import argparse
import httpx

# Parse args early so we can set FASTMCP_ env vars before FastMCP construction.
_parser = argparse.ArgumentParser(description="Cryptic MCP Admin Server")
_parser.add_argument("--sse", action="store_true", help="Use SSE transport instead of stdio")
_parser.add_argument("--port", type=int, default=9090, help="Port for SSE transport (default: 9090)")
_parser.add_argument("--host", default="127.0.0.1", help="Host to bind for SSE transport (default: 127.0.0.1)")
_args = _parser.parse_args()

if _args.sse:
    os.environ["FASTMCP_PORT"] = str(_args.port)
    os.environ["FASTMCP_HOST"] = _args.host

from mcp.server.fastmcp import FastMCP

DEFAULT_BASE_URL = "http://127.0.0.1:8081/mcp/v1/admin"

_mcp_kwargs = {}
if _args.sse:
    _mcp_kwargs["host"] = _args.host
    _mcp_kwargs["port"] = _args.port

mcp = FastMCP(
    "Cryptic Admin",
    instructions=(
        "You are an admin assistant for the Cryptic end-to-end encrypted "
        "messaging server. Use these tools to inspect server state, manage "
        "users, and review audit logs. All operations require a valid admin "
        "GPG fingerprint."
    ),
    **_mcp_kwargs,
)


def _base_url() -> str:
    return os.environ.get("CRYPTIC_MCP_BASE_URL", DEFAULT_BASE_URL)


def _admin_fp() -> str:
    fp = os.environ.get("CRYPTIC_ADMIN_GPG_FP", "")
    if not fp:
        raise ValueError(
            "CRYPTIC_ADMIN_GPG_FP environment variable must be set "
            "to the admin's GPG fingerprint"
        )
    return fp


def _headers() -> dict[str, str]:
    return {"X-Admin-GPG-FP": _admin_fp()}


def _get(path: str, params: dict | None = None) -> dict:
    """Perform a GET request to the Cryptic admin API."""
    url = f"{_base_url()}{path}"
    with httpx.Client(timeout=30) as client:
        resp = client.get(url, headers=_headers(), params=params)
        resp.raise_for_status()
        return resp.json()


def _post(path: str, body: dict | None = None) -> dict:
    """Perform a POST request to the Cryptic admin API."""
    url = f"{_base_url()}{path}"
    with httpx.Client(timeout=30) as client:
        resp = client.post(url, headers=_headers(), json=body or {})
        resp.raise_for_status()
        return resp.json()


# ── Read-only tools ──────────────────────────────────────────────────

@mcp.tool()
def server_status() -> dict:
    """Get an overview of the Cryptic server.

    Returns listener status, ETS table sizes, and CA identity counts.
    """
    return _get("/status")


@mcp.tool()
def list_users(filter: str | None = None) -> dict:
    """List all registered users.

    Args:
        filter: Optional status filter: "active", "suspended", or "revoked".
    """
    params = {}
    if filter:
        params["filter"] = filter
    return _get("/list_users", params=params)


@mcp.tool()
def get_user_info(gpg_fp: str) -> dict:
    """Get detailed information about a specific user.

    Args:
        gpg_fp: The user's GPG fingerprint.
    """
    return _get(f"/user/{gpg_fp}")


@mcp.tool()
def list_online_users() -> dict:
    """List users that are currently connected to the server."""
    return _get("/online")


@mcp.tool()
def list_connections() -> dict:
    """Show detailed WebSocket connection info.

    Returns per-connection process stats (memory, message queue, reductions).
    """
    return _get("/connections")


@mcp.tool()
def list_pending_messages(user: str | None = None) -> dict:
    """Show pending (offline-queued) messages.

    Args:
        user: If provided, show pending messages for this specific user only.
              Otherwise returns a per-user summary.
    """
    if user:
        return _get(f"/pending/{user}")
    return _get("/pending")


@mcp.tool()
def list_key_bundles(user: str | None = None) -> dict:
    """Show uploaded X3DH key bundle information.

    Args:
        user: If provided, show detailed key bundle for this user.
              Otherwise returns a summary for all users.
    """
    if user:
        return _get(f"/keys/{user}")
    return _get("/keys")


@mcp.tool()
def list_certificates(gpg_fp: str) -> dict:
    """List TLS certificates for a user.

    Args:
        gpg_fp: The user's GPG fingerprint.
    """
    return _get(f"/user/{gpg_fp}/certificates")


@mcp.tool()
def get_audit_log(limit: int = 20) -> dict:
    """Retrieve recent audit log entries.

    Args:
        limit: Maximum number of entries to return (default 20).
    """
    return _get("/audit", params={"limit": str(limit)})


# ── Write tools ──────────────────────────────────────────────────────

@mcp.tool()
def register_user(gpg_fp: str, gpg_pub: str, metadata: str | None = None) -> dict:
    """Register a new user on the Cryptic server.

    Args:
        gpg_fp: The new user's GPG fingerprint.
        gpg_pub: The new user's ASCII-armored GPG public key.
        metadata: Optional JSON metadata string.
    """
    body: dict = {"gpg_fp": gpg_fp, "gpg_pub": gpg_pub}
    if metadata is not None:
        body["metadata"] = metadata
    return _post("/register_user", body)


@mcp.tool()
def suspend_user(gpg_fp: str, reason: str | None = None) -> dict:
    """Suspend a user, preventing them from connecting.

    Args:
        gpg_fp: The GPG fingerprint of the user to suspend.
        reason: Optional reason for the suspension.
    """
    body: dict = {"gpg_fp": gpg_fp}
    if reason:
        body["reason"] = reason
    return _post("/suspend_user", body)


@mcp.tool()
def reactivate_user(gpg_fp: str) -> dict:
    """Reactivate a previously suspended user.

    Revoked users cannot be reactivated.

    Args:
        gpg_fp: The GPG fingerprint of the user to reactivate.
    """
    return _post("/reactivate_user", {"gpg_fp": gpg_fp})


@mcp.tool()
def revoke_user(gpg_fp: str, reason: str | None = None) -> dict:
    """Permanently revoke a user. This action cannot be reversed.

    Args:
        gpg_fp: The GPG fingerprint of the user to revoke.
        reason: Optional reason for the revocation.
    """
    body: dict = {"gpg_fp": gpg_fp}
    if reason:
        body["reason"] = reason
    return _post("/revoke_user", body)


@mcp.tool()
def revoke_certificate(serial: str, reason: str) -> dict:
    """Revoke a specific TLS certificate.

    Args:
        serial: The certificate serial number.
        reason: The reason for revocation.
    """
    return _post("/revoke_certificate", {"serial": serial, "reason": reason})


# ── Enrollment tools ─────────────────────────────────────────────────

@mcp.tool()
def list_enrollments(filter: str | None = None) -> dict:
    """List mobile enrollment identities.

    Args:
        filter: Optional status filter: "active", "consumed", "suspended", or "revoked".
    """
    params = {}
    if filter:
        params["filter"] = filter
    return _get("/enrollments", params=params)


@mcp.tool()
def get_enrollment_info(enrollment_fp: str) -> dict:
    """Get detailed information about a mobile enrollment identity.

    Args:
        enrollment_fp: The enrollment fingerprint (SHA-256 hex of Ed25519 public key).
    """
    return _get(f"/enrollment/{enrollment_fp}")


@mcp.tool()
def register_enrollment(
    enrollment_fp: str,
    enrollment_pub: str,
    username: str,
    metadata: str | None = None,
) -> dict:
    """Register a new mobile enrollment identity.

    Args:
        enrollment_fp: SHA-256 hex fingerprint of the Ed25519 public key.
        enrollment_pub: Base64-encoded 32-byte Ed25519 public key.
        username: Username to associate with the enrollment.
        metadata: Optional JSON metadata string.
    """
    body: dict = {
        "enrollment_fp": enrollment_fp,
        "enrollment_pub": enrollment_pub,
        "username": username,
    }
    if metadata is not None:
        body["metadata"] = metadata
    return _post("/register_enrollment", body)


@mcp.tool()
def suspend_enrollment(enrollment_fp: str, reason: str | None = None) -> dict:
    """Suspend a mobile enrollment, preventing certificate issuance.

    Args:
        enrollment_fp: The enrollment fingerprint to suspend.
        reason: Optional reason for the suspension.
    """
    body: dict = {"enrollment_fp": enrollment_fp}
    if reason:
        body["reason"] = reason
    return _post("/suspend_enrollment", body)


@mcp.tool()
def reactivate_enrollment(enrollment_fp: str) -> dict:
    """Reactivate a previously suspended mobile enrollment.

    Revoked enrollments cannot be reactivated.

    Args:
        enrollment_fp: The enrollment fingerprint to reactivate.
    """
    return _post("/reactivate_enrollment", {"enrollment_fp": enrollment_fp})


@mcp.tool()
def revoke_enrollment(enrollment_fp: str, reason: str | None = None) -> dict:
    """Permanently revoke a mobile enrollment. This action cannot be reversed.

    Args:
        enrollment_fp: The enrollment fingerprint to revoke.
        reason: Optional reason for the revocation.
    """
    body: dict = {"enrollment_fp": enrollment_fp}
    if reason:
        body["reason"] = reason
    return _post("/revoke_enrollment", body)


@mcp.tool()
def delete_enrollment(enrollment_fp: str) -> dict:
    """Completely delete a mobile enrollment identity.

    Removes all traces of the enrollment from the database so the
    mobile enrollment flow can be retried from scratch. Intended for
    debugging purposes.

    Args:
        enrollment_fp: The enrollment fingerprint to delete.
    """
    return _post("/delete_enrollment", {"enrollment_fp": enrollment_fp})


@mcp.tool()
def server_log(lines: int = 50) -> dict:
    """Get the tail of the Cryptic server log.

    Useful for debugging errors or inspecting recent server activity.

    Args:
        lines: Number of lines to return from the end of the log (1-1000, default 50).
    """
    return _get("/server_log", {"lines": lines})


def main():
    """Run the MCP server.

    Supports two transports:
      - stdio (default): for local use via VS Code's "stdio" MCP type.
      - sse: listens on a TCP port for remote/tunneled connections.

    Usage:
      cryptic-mcp-server                    # stdio (default)
      cryptic-mcp-server --sse              # SSE on default port 9090
      cryptic-mcp-server --sse --port 9091  # SSE on custom port
      cryptic-mcp-server --sse --host 0.0.0.0  # Bind to all interfaces
    """
    if _args.sse:
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
