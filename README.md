# Cryptic - End-to-End Encrypted Chat System

> **⚠️ DISCLAIMER**
>
> This is an **educational implementation** of cryptographic protocols, created
> for learning purposes. It has **not been audited** and may contain security
> vulnerabilities.
>
> Cryptographic software is extremely difficult to implement correctly.
> Even small mistakes can completely undermine security.
>
> **NO WARRANTIES** of any kind. Use at your own risk. For production needs,
> use professionally audited solutions like Signal or Matrix.

**Cryptic** is an end-to-end encrypted chat system built in Erlang/OTP. Clients
authenticate with mutual-TLS client certificates over a WebSocket connection, and
messages are encrypted with the [X3DH](https://signal.org/docs/specifications/x3dh/)
and [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
protocols.

The **server** relays messages between clients, stores their public key bundles,
queues encrypted messages until the recipient comes online, and runs a small CA
that enrolls new clients. Users chat from a [mobile client app](https://github.com/etnt/cryptic-mobile).

## Quick start: run the server

The server ships as a multi-arch (amd64/arm64) container image. It exposes ports
`8443` (encrypted messaging + CA) and `8444` (web admin).

```bash
# 1. Pull the latest release image (or a specific version, e.g. :1.0.0)
podman pull ghcr.io/etnt/cryptic:latest

# 2. Create an admin password hash (no plaintext in the container)
# NOTE: change 'CHANGE-ME' below to a proper password!
# --entrypoint runs the hashing tool directly, so only the hash is written
# to the file (without it, the container's startup logs get captured too).
mkdir -p server_data secrets
rm -f secrets/admin_hash
podman run --rm --entrypoint cryptic-hash-admin-password \
  ghcr.io/etnt/cryptic:latest 'CHANGE-ME' > secrets/admin_hash

# 3. Run
podman run -d --name cryptic-server \
  -p 0.0.0.0:8443:8443 -p 0.0.0.0:8444:8444 \
  -v cryptic-ca-data:/opt/cryptic/server_data/data \
  -v "$PWD/server_data:/opt/cryptic/server_data" \
  -v "$PWD/secrets/admin_hash:/run/secrets/cryptic_admin_hash:ro" \
  -e CRYPTIC_SERVER_DIR=/opt/cryptic/server_data \
  -e CRYPTIC_WEBADMIN_ENABLED=true \
  -e CRYPTIC_ADMIN_PASSWORD_HASH_FILE=/run/secrets/cryptic_admin_hash \
  -e CRYPTIC_PUBLIC_HOST=localhost \
  ghcr.io/etnt/cryptic:latest
```

Prefer to build it yourself? Replace step 1 with
`podman build -t ghcr.io/etnt/cryptic:latest -f Dockerfile .`.

Set `CRYPTIC_PUBLIC_HOST` to the address phones actually reach the server on (its
LAN IP or a DNS name) — it is embedded in enrollment packages and must be covered
by the server certificate. `docker` works too; substitute it for `podman`.

Full build/run details (registry short-names, the CA database volume, graceful
shutdown, Raspberry Pi, all environment variables) are in [DOCKER.md](DOCKER.md).

## Enroll a mobile client

1. Open the web admin at `https://localhost:8444` and log in as `admin`.
2. Create an enrollment for the new username and choose the server host the phone
   will connect to. This produces an enrollment package, shown as a QR code.
3. In the mobile app, scan the QR code (or paste the package). The app pins the
   server's CA by fingerprint, requests its client certificate, and is then ready
   to message other enrolled users.

## References

- The [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- The [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)

## License

Mozilla Public License Version 2.0
