# Building & Running the Cryptic Server Image (podman)

Operational cheat-sheet for building the Cryptic **server** image from source and
running it as a container with `podman`. This covers the fiddly bits (registry
short-name resolution, admin password hashing, the CA DB named volume, graceful
shutdown, LAN/mobile access, Raspberry Pi) that are easy to get wrong.

> This is the *build-from-source* workflow. For the published `ghcr.io` images and
> the TUI client, see [docs/DOCKER.md](docs/DOCKER.md).

---

## Quick summary

```bash
# 1. Build the server image (GIT_REF stamps the source revision into the image)
podman build \
  --build-arg GIT_REF="$(git describe --tags --always --dirty)" \
  -t cryptic-server:latest -f Dockerfile .

# 2. Hash an admin password (no plaintext in the container)
mkdir -p server_data secrets
rm -f secrets/admin_hash   # clear any empty leftover from a failed redirect
podman run --rm localhost/cryptic-server:latest \
  cryptic-hash-admin-password 'CHANGE-ME' > secrets/admin_hash

# 3. Run the container
podman run -d --name cryptic-server \
  -p 0.0.0.0:8443:8443 -p 0.0.0.0:8444:8444 \
  -v cryptic-ca-data:/opt/cryptic/server_data/data \
  -v "$PWD/server_data:/opt/cryptic/server_data" \
  -v "$PWD/secrets/admin_hash:/run/secrets/cryptic_admin_hash:ro" \
  -e CRYPTIC_SERVER_HOST=0.0.0.0 \
  -e CRYPTIC_SERVER_PORT=8443 \
  -e CRYPTIC_SERVER_DIR=/opt/cryptic/server_data \
  -e CRYPTIC_WEBADMIN_ENABLED=true \
  -e CRYPTIC_WEBADMIN_PORT=8444 \
  -e CRYPTIC_ADMIN_USER=admin \
  -e CRYPTIC_ADMIN_PASSWORD_HASH_FILE=/run/secrets/cryptic_admin_hash \
  localhost/cryptic-server:latest
```

---

## 1. Build

```bash
podman build \
  --build-arg GIT_REF="$(git describe --tags --always --dirty)" \
  -t cryptic-server:latest -f Dockerfile .
```

The image is a multi-stage build (`erlang:28.1-alpine` builder + runtime). The
resulting image is tagged locally as `localhost/cryptic-server:latest` — always
use that fully-qualified name in `podman run` to avoid short-name lookups.

The `--build-arg GIT_REF=...` stamps the source revision into the image as an
OCI label (and a `CRYPTIC_GIT_REF` env var) so you can later tell exactly which
tag/commit a built image came from — see [section 8](#8-checking-the-image-version).
It's optional; omit it and the revision records as `unknown`.

### Base-image short-name errors (fresh podman)

On a fresh podman install (e.g. Debian on a Raspberry Pi) with no
`unqualified-search-registries` configured, the build fails with:

```
error: short-name "erlang:28.1-alpine" did not resolve to an alias ...
```

Two fixes (either works; the first is permanent and portable):

1. **Fully-qualified base images (already applied in the Dockerfile).**
   Both `FROM` lines use `docker.io/library/erlang:28.1-alpine`, so no registry
   search config is needed. Just make sure the host has this version of the
   Dockerfile (`git pull` on that machine).

2. **Host-side registry drop-in** (unblocks any short-name image immediately):

   ```bash
   sudo mkdir -p /etc/containers/registries.conf.d
   printf 'unqualified-search-registries = ["docker.io"]\n' | \
     sudo tee /etc/containers/registries.conf.d/00-docker.conf
   ```

### NIF architecture flag

The Dockerfile builds the C NIF with a hardcoded arch:

```dockerfile
RUN cd c_src && make clean && UNAME_ARCH=aarch64 make
```

`aarch64` is correct for **Apple Silicon Macs** and **64-bit Raspberry Pi OS**
(`uname -m` → `aarch64`). It will **not** work on `x86_64` or 32-bit `armv7l`
hosts. To make it portable, change the flag to `UNAME_ARCH=$(uname -m)`.

---

## 2. Admin password

The server never needs plaintext. Produce a hash record offline and mount it
read-only:

```bash
mkdir -p secrets
rm -f secrets/admin_hash                 # a failed `>` leaves an empty file that breaks bootstrap
podman run --rm localhost/cryptic-server:latest \
  cryptic-hash-admin-password 'your-strong-password' > secrets/admin_hash
```

Then reference it with `CRYPTIC_ADMIN_PASSWORD_HASH_FILE=/run/secrets/cryptic_admin_hash`
and mount `secrets/admin_hash` at that path (see run command below).

> If you skip this, leave `CRYPTIC_ADMIN_PASSWORD` empty and the server generates
> a random password, printed **once** to the log on first boot.

---

## 3. Run

```bash
mkdir -p server_data secrets

podman run -d --name cryptic-server \
  -p 0.0.0.0:8443:8443 \
  -p 0.0.0.0:8444:8444 \
  -v cryptic-ca-data:/opt/cryptic/server_data/data \
  -v "$PWD/server_data:/opt/cryptic/server_data" \
  -v "$PWD/secrets/admin_hash:/run/secrets/cryptic_admin_hash:ro" \
  -e CRYPTIC_SERVER_HOST=0.0.0.0 \
  -e CRYPTIC_SERVER_PORT=8443 \
  -e CRYPTIC_SERVER_DIR=/opt/cryptic/server_data \
  -e CRYPTIC_WEBADMIN_ENABLED=true \
  -e CRYPTIC_WEBADMIN_PORT=8444 \
  -e CRYPTIC_ADMIN_USER=admin \
  -e CRYPTIC_ADMIN_PASSWORD_HASH_FILE=/run/secrets/cryptic_admin_hash \
  localhost/cryptic-server:latest
```

Ports:
- `8443` — WebSocket mTLS (client protocol) + CA REST (`/ca/v1/*`, `/ca/v1/ca-cert` is public)
- `8444` — web admin HTTPS

### The CA DB named-volume mount (important)

```
-v cryptic-ca-data:/opt/cryptic/server_data/data
```

This nested named volume **shadows** `server_data/data` so the CA SQLite DB lives
on the container-engine's ext4 volume, **not** on the host bind mount. On macOS,
running SQLite over the virtiofs bind mount corrupts the DB (recurring
`SQLITE_NOTADB` / zeroed header). Keep this mount. `priv/ssl` (CA key/cert) and
`logs/` still land on the `server_data` bind mount.

mTLS certificates are auto-generated into `server_data/priv/ssl` on first run and
persist across restarts.

---

## 4. LAN / mobile access

Phones enrolling over the LAN need the enrollment package to embed a host they can
actually reach. Set `CRYPTIC_PUBLIC_HOST` to the server's LAN IP:

```bash
  -e CRYPTIC_PUBLIC_HOST=192.168.1.50 \
```

(iOS Simulator shares the Mac's network, so `localhost` works there without this.)

---

## 5. Lifecycle

```bash
# Logs
podman logs -f cryptic-server

# Health / status
podman ps
podman healthcheck run cryptic-server

# Verify the public CA cert endpoint
curl -k https://localhost:8443/ca/v1/ca-cert -o /dev/null -w '%{http_code}\n'

# Which source revision is this image? (see section 8)
podman image inspect cryptic-server:latest \
  --format '{{index .Labels "org.opencontainers.image.revision"}}'
```

### Always stop gracefully before removing

```bash
podman stop cryptic-server      # SIGTERM, lets SQLite finish writes
podman rm cryptic-server
```

**Never** `podman rm -f` a running container. A SIGKILL mid-SQLite-write zeroes the
CA DB header → `SQLITE_NOTADB` (error 26) on next boot. The CA DB survives on the
`cryptic-ca-data` named volume across `stop`/`rm`/recreate as long as you shut down
cleanly.

### Rebuild & recreate on a new image

```bash
podman build -t cryptic-server:latest -f Dockerfile .
podman stop cryptic-server && podman rm cryptic-server
# re-run the `podman run -d ...` from section 3 (CA data persists on the volume)
```

See section 6 for the full upgrade procedure and what does/doesn't survive.

---

## 6. Upgrading to a new build (without resetting enrolled users)

The container image bundles a compiled release, so **new `.erl` code needs a
rebuilt (or re-pulled) image** — restarting the existing container alone won't
pick up your changes. There's no Erlang hot-code-upgrade wired up (no
relup/appup), so the path is: get the new image → replace the container →
reuse the same volumes.

None of the enrollment state lives in the image or the container's writable
layer, so swapping the container is safe.

### What persists vs. what's ephemeral

**Persisted (survives an image/container swap):**
- **CA SQLite DB** — enrolled GPG identities, issued client certs, revocations,
  audit log → the `cryptic-ca-data` **named volume** (`/opt/cryptic/server_data/data`).
- **CA key/cert + server TLS certs** → `server_data/priv/ssl` (bind mount).
- **Admin password hash** → `secrets/admin_hash` (bind mount).

**In-memory ETS (lost on every restart — but self-heals):**
- Uploaded identity keys + prekey bundles → clients **re-upload these on
  reconnect**, so no re-enrollment is needed.
- Online-connection table → rebuilt as clients reconnect.
- **Queued messages for offline users → lost.** Anything not yet delivered does
  not survive. (Have the recipient reconnect *after* the upgrade so your next
  message re-queues on the new build.)

mTLS auth keeps working after the swap because it validates against the CA DB +
CA cert, both on the preserved volumes.

### The golden rule

**Do not delete the `cryptic-ca-data` volume or the `server_data` / `secrets`
directories.** Never `podman volume rm cryptic-ca-data`, and never pass `-v` to
`podman rm` (that would remove attached anonymous volumes). Recreating the
*container* is fine; deleting the *volume* is what wipes accounts.

### Procedure (build-from-source)

```bash
cd /path/to/cryptic
git pull                                    # get the new code

podman build \
  --build-arg GIT_REF="$(git describe --tags --always --dirty)" \
  -t cryptic-server:latest -f Dockerfile .
podman stop cryptic-server && podman rm cryptic-server   # NOT -v; stop first
# re-run the exact `podman run -d ...` from section 3 — same volumes & env
```

With compose it's a one-liner (it reuses the same volume + bind mounts):

```bash
git pull
GIT_REF="$(git describe --tags --always --dirty)" \
  podman compose up -d --build cryptic-server
```

### Procedure (published ghcr.io image)

If you run the prebuilt image instead of building locally, the fix has to reach
the registry first (push → CI republishes `ghcr.io/etnt/cryptic:latest`), then:

```bash
podman compose pull cryptic-server
podman compose up -d cryptic-server         # same volumes, new image
```

### Verify

```bash
podman compose logs -f cryptic-server       # comes up cleanly, no crash loop
podman volume ls | grep cryptic-ca-data     # volume still present
curl -k https://localhost:8443/ca/v1/ca-cert -o /dev/null -w '%{http_code}\n'
```

Expect brief downtime during the restart; clients reconnect and re-upload their
keys on their own.

---

## 7. Raspberry Pi 4 (64-bit)

1. Confirm 64-bit OS: `uname -m` → `aarch64` (matches the Dockerfile's NIF flag).
2. Get the source onto the Pi (`git pull` in its own clone) so it has the
   fully-qualified `FROM` lines, **or** apply the registries drop-in from
   section 1.
3. Build, hash the admin password, and run exactly as above, using the
   `localhost/cryptic-server:latest` image name.
4. Set `CRYPTIC_PUBLIC_HOST` to the Pi's LAN IP so phones on the network can enroll.

---

## 8. Checking the image version

A local `:latest` tag says nothing about *which* source revision it was built
from — two builds from different commits produce indistinguishable `:latest`
images. So the Dockerfile stamps the git revision into every image when you pass
`--build-arg GIT_REF=...` (see [section 1](#1-build)).

### Read the revision from an image

```bash
podman image inspect cryptic-server:latest \
  --format '{{index .Labels "org.opencontainers.image.revision"}}'
#   → v1.2.0-3-gab12cde        (nearest tag + commits-since + short sha)
#   → v1.2.0-3-gab12cde-dirty  (…tree had uncommitted changes at build time)
#   → unknown                  (built without the --build-arg)
```

`git describe --tags --always --dirty` gives the nearest tag, how many commits
you are past it, the short SHA, and a `-dirty` suffix if the working tree wasn't
clean — exactly what you want to know about a running server.

### Read it from a running container

The same value is exposed as an env var, so you can ask a live container without
inspecting the image:

```bash
podman exec cryptic-server printenv CRYPTIC_GIT_REF
```

### Other intrinsic clues (when no revision was stamped)

```bash
podman image inspect cryptic-server:latest --format '{{.Created}}'   # build time
```

Note: the app's internal `{vsn, "1.0.0"}` in `src/cryptic.app.src` is a
hand-maintained release string, **not** the git tag — don't rely on it to
identify a build.

---

## Environment variable reference

| Variable | Default | Purpose |
| --- | --- | --- |
| `CRYPTIC_SERVER_HOST` | `0.0.0.0` | Bind address for the WSS listener |
| `CRYPTIC_SERVER_PORT` | `8443` | WSS mTLS + CA REST port |
| `CRYPTIC_SERVER_DIR` | `/opt/cryptic/server_data` | Root for `priv/`, `data/`, `logs/` |
| `CRYPTIC_PUBLIC_HOST` | (unset) | Host embedded in enrollment packages (set to LAN IP) |
| `CRYPTIC_WEBADMIN_ENABLED` | `true` | Enable the web admin endpoint |
| `CRYPTIC_WEBADMIN_PORT` | `8444` | Web admin HTTPS port |
| `CRYPTIC_ADMIN_USER` | `admin` | Seeded admin username (first boot only) |
| `CRYPTIC_ADMIN_PASSWORD_HASH_FILE` | (unset) | Path to mounted hash record (preferred) |
| `CRYPTIC_ADMIN_PASSWORD_FILE` | (unset) | Path to mounted plaintext password (discouraged) |
| `CRYPTIC_ADMIN_PASSWORD` | (unset) | Plaintext via env (discouraged; empty ⇒ random) |
| `CRYPTIC_EVENT_HANDLERS` | `cryptic_file_logger` | Event handler modules |
| `CRYPTIC_DEBUG` | `false` | Verbose entrypoint + app logging |
| `CRYPTIC_GIT_REF` | `unknown` | Source revision stamped at build via `--build-arg GIT_REF` (see section 8) |

---

## Notes

- Uses native `podman` (`/opt/homebrew/bin/podman` on the dev Mac). Substitute
  `docker` if you use Docker Desktop; the mounts/env are identical.
- `docker-compose.yml` at the repo root wires all of this up declaratively
  (`podman compose up -d` / `docker compose up -d`) — this file documents the
  manual equivalents and the reasoning behind the tricky mounts.
