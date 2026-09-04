# Cryptic Server — Quick Start

This guide gets a Cryptic server running and walks you through creating the
initial **web admin** account so you can manage users and issue mobile
enrollment packages.

Two paths are covered:

- **[A. Docker / Podman Compose](#a-docker--podman-compose-recommended)** — the recommended way to run a server.
- **[B. Local build](#b-local-build-from-source)** — running from source for development.

By the end you will have:

- A WebSocket mTLS endpoint for chat clients on **port 8443**.
- A web administration UI (HTTPS, password login) on **port 8444**.
- One admin account to log in with.

---

## What the server provisions automatically

On first boot the server is self-provisioning — there is **no manual GPG or
certificate step**:

1. **mTLS certificates** — if `priv/ssl/ca.crt` / `ca.key` are missing, the
   entrypoint generates a fresh self-signed CA + server certificate onto the
   mounted data volume. They persist across restarts.
2. **Initial admin account** — if *no* admin account exists yet, the server
   seeds exactly one. This is **idempotent**: once an admin exists, restarts
   never reset or overwrite it.

---

## A. Docker / Podman Compose (recommended)

### 1. Choose how the first admin password is set

The bootstrap picks a password source in this priority order (first match wins):

| Priority | Source | Env var | Notes |
|----------|--------|---------|-------|
| 1 | Pre-hashed record file | `CRYPTIC_ADMIN_PASSWORD_HASH_FILE` | **Preferred.** No plaintext ever enters the container. |
| 2 | Plaintext password file | `CRYPTIC_ADMIN_PASSWORD_FILE` | Docker/Podman secret. Forces a password change on first login. |
| 3 | Plaintext env var | `CRYPTIC_ADMIN_PASSWORD` | Discouraged (leaks via `inspect`). Forces a change on first login. |
| 4 | *(nothing set)* | — | A random password is generated and **printed once to the log**. |

The admin username defaults to `admin` and can be overridden with
`CRYPTIC_ADMIN_USER`.

#### Option 1 — Pre-hashed record (recommended)

Generate a hash record **offline** (nothing secret touches the server):

```bash
# From a source checkout:
echo -n 'my-strong-passphrase' | ./scripts/cryptic-hash-admin-password.escript

# Or, using the helper baked into the server image:
echo -n 'my-strong-passphrase' | \
  docker run --rm -i --entrypoint cryptic-hash-admin-password ghcr.io/etnt/cryptic:latest
```

This prints one line, e.g.:

```
pbkdf2_hmac_sha256$210000$32$CpXO1cX1Kh37JRqWmgIDOw==$y8SgttVV+vN7QbpZcBQPXwdENfnfAUd/5n7B8/p73VU=
```

Save it to a file and mount it read-only:

```bash
mkdir -p secrets
echo -n 'my-strong-passphrase' | \
  ./scripts/cryptic-hash-admin-password.escript > secrets/admin_hash
```

Then in `docker-compose.yml`, under the `cryptic-server` service, uncomment:

```yaml
    environment:
      - CRYPTIC_ADMIN_PASSWORD_HASH_FILE=/run/secrets/cryptic_admin_hash
    volumes:
      - ./secrets/admin_hash:/run/secrets/cryptic_admin_hash:ro
```

#### Option 2 — Plaintext password file

```bash
mkdir -p secrets
printf 'my-strong-passphrase' > secrets/admin_password
```

```yaml
    environment:
      - CRYPTIC_ADMIN_PASSWORD_FILE=/run/secrets/cryptic_admin_password
    volumes:
      - ./secrets/admin_password:/run/secrets/cryptic_admin_password:ro
```

#### Option 3 — Let the server generate one

Leave all `CRYPTIC_ADMIN_PASSWORD*` values unset. After first boot, read the
password from the log (see step 3). You will be asked to change it on first
login.

> Passwords must be at least **12 characters**.

### 2. Start the server

```bash
# Build and start (foreground)
docker compose up --build cryptic-server

# …or detached
docker compose up -d --build cryptic-server
```

Podman users can substitute `podman compose` (see [Podman notes](#podman-notes)).

### 3. Find the admin credentials (only if you chose Option 3)

```bash
docker compose logs cryptic-server | grep -A2 "Admin bootstrap"
```

You will see a line similar to:

```
Admin bootstrap: no password provided. Generated a random password for user 'admin': 3xAmpl3-r4nd0m_pw
  >>> Save it now and change it on first login. It is not stored and will not be shown again.
```

### 4. Open the web admin

Navigate to:

```
https://localhost:8444/admin
```

The certificate is self-signed, so accept the browser warning (or import the
generated `server_data/priv/ssl/ca.crt` into your trust store). Log in with your
admin username and password.

---

## B. Local build (from source)

### Prerequisites

- Erlang/OTP 28.x
- `rebar3`
- `libsodium`, `libargon2`, `sqlite3` development libraries
- `openssl`

### 1. Build

```bash
rebar3 compile
```

### 2. Generate mTLS certificates (first time only)

```bash
DIR=priv/ssl ./scripts/generate-mtls-certs.sh
```

### 3. Start with the web admin enabled + initial admin

The admin bootstrap runs during application startup, so set the environment
variables **before** launching:

```bash
# Preferred: seed from an offline hash record
export CRYPTIC_WEBADMIN_ENABLED=true
export CRYPTIC_WEBADMIN_PORT=8444
export CRYPTIC_ADMIN_USER=admin
echo -n 'my-strong-passphrase' | \
  ./scripts/cryptic-hash-admin-password.escript > /tmp/admin_hash
export CRYPTIC_ADMIN_PASSWORD_HASH_FILE=/tmp/admin_hash

./scripts/start-server.sh
```

Alternatives: set `CRYPTIC_ADMIN_PASSWORD_FILE`, or `CRYPTIC_ADMIN_PASSWORD`, or
leave them all unset to get a randomly generated password printed to
`logs/server.log`.

Then open `https://localhost:8444/admin`.

---

## First login & everyday admin tasks

- **Change password** — if the account was seeded from a plaintext source (or a
  random password), you are prompted to set a new one on first login.
- **Inspect / manage users** — the *Users* section lists registered users; you
  can view certificates and suspend, reactivate, or revoke accounts.
- **Create a mobile enrollment** — in the *Enrollments* section choose **New
  enrollment**, enter the username and a one-time passphrase, and share the
  generated QR code / package with the user. Enrollment uses Ed25519 identities.
- **Monitor logs** — the *Logs* section streams `logs/server.log` live and lets
  you filter by level or text.

---

## Environment variable reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `CRYPTIC_SERVER_HOST` | `0.0.0.0` (container) / `localhost` | Bind address for the WebSocket endpoint. |
| `CRYPTIC_SERVER_PORT` | `8443` | WebSocket mTLS port. |
| `CRYPTIC_SERVER_DIR` | `/opt/cryptic/server_data` (container) | Root for `priv/`, `logs/`, `data/`. |
| `CRYPTIC_WEBADMIN_ENABLED` | `true` (container) | Enable the web admin HTTPS endpoint (`1`/`true`/`yes`/`on`). |
| `CRYPTIC_WEBADMIN_PORT` | `8444` | Web admin HTTPS port. |
| `CRYPTIC_ADMIN_USER` | `admin` | Username for the seeded admin account. |
| `CRYPTIC_ADMIN_PASSWORD_HASH_FILE` | — | Path to an offline PBKDF2 hash record (preferred). |
| `CRYPTIC_ADMIN_PASSWORD_FILE` | — | Path to a plaintext password file (forces change on first login). |
| `CRYPTIC_ADMIN_PASSWORD` | — | Plaintext password env var (discouraged; forces change). |
| `CRYPTIC_CERT_DNS_SANS` | `CRYPTIC_SERVER_HOST` | Comma-separated DNS SANs for the auto-generated server certificate. |
| `CRYPTIC_DEBUG` | `false` | Verbose logging. |

---

## Podman notes

The image runs rootless under Podman. When bind-mounting volumes on an
SELinux-enabled host, add the `:Z` label so the container can read/write:

```bash
podman run ... -v ./server_data:/opt/cryptic/server_data:rw,Z ...
```

With `podman compose`, add `:Z` to the volume entries in `docker-compose.yml`
if you hit permission errors. Verify the mounted `server_data` directory is
writable by your mapped UID.

---

## Troubleshooting

- **Can't reach `https://localhost:8444/admin`** — confirm `CRYPTIC_WEBADMIN_ENABLED`
  is truthy and port `8444` is published/open. `docker compose logs cryptic-server`
  should show `Starting web admin HTTPS endpoint on port 8444`.
- **No admin bootstrap message in the log** — an admin already exists; the
  bootstrap is idempotent and skips seeding. To start fresh, clear the CA
  database under `server_data/` (this removes all accounts).
- **`password must be at least 12 characters`** — the supplied password is too
  short; choose a longer one and re-seed.
- **Certificate warnings** — expected with the self-signed default cert. Import
  `server_data/priv/ssl/ca.crt` into your OS/browser trust store to silence them,
  or supply your own certificates in `priv/ssl/`.

---

## Where things live

```
server_data/
├── priv/ssl/          # auto-generated CA + server certificates
├── data/              # CA database (users, admin accounts, enrollments)
└── logs/server.log    # server log (streamed by the web admin Logs view)
```
