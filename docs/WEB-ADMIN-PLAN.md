# Cryptic Web Administration — Implementation Plan

> Status: **Draft for review**
> Scope: A browser-based admin console for the Cryptic server, replacing/augmenting the
> existing Erlang shell (`cryptic_admin`), MCP admin endpoint, and `cryptic-onboard` CLI,
> plus **turnkey container packaging** (Docker/Podman) so a fresh server is trivial to deploy.

## 1. Goals

The first release must support:

1. **Secure login** — username + password over HTTPS, with server-side sessions.
2. **User administration** — inspect and manipulate users (list, view detail, suspend,
   reactivate, revoke, view certificates, view enrollments) — parity with what the
   shell/MCP admin can do today.
3. **Mobile enrollment** — produce an enrollment package for a new mobile user and
   render it as a QR code (plus copy-to-clipboard for simulators), entirely from the
   browser — no shell access to `cryptic-onboard` required.
4. **Log monitoring** — live tail of `logs/server.log` plus a paged historical view for
   troubleshooting.
5. **Turnkey container deployment** — a Docker/Podman image that boots a working server with
   **no GPG setup**, self-provisions its CA/server certs on first run, and creates the initial
   admin account from configuration/secrets so the operator can log in to the web admin
   immediately.

## 2. Confirmed design decisions

| Area | Decision |
|------|----------|
| Auth model | New `admin_accounts` table (username + **PBKDF2-HMAC-SHA256** password hash) + signed, HTTP-only session cookie. Decoupled from GPG identities. |
| Frontend | Server-rendered HTML shell + **vanilla JS**, talking to a JSON API. Served from `priv/webadmin/`. **No Node/build step.** |
| Transport | **New dedicated HTTPS listener** on a separate admin port (default **8444**), server-cert TLS, **no client cert required**. Isolated from the 8443 mTLS messaging listener and the 8081 localhost MCP endpoint. |
| Log streaming | Live tail via **WebSocket** + paged historical view over the JSON API. |
| Packaging | Single Docker/Podman image; **GPG dropped** in favour of the Ed25519 enrollment flow; certs auto-provisioned on first run; initial admin seeded from env/secret. |

## 3. Current-state summary (what we build on)

- **HTTP stack**: Cowboy 2.9.0 / Ranch 2.1.0, JSON via `jsx` 3.1.0 — all already deps.
  See [rebar.config](../rebar.config).
- **Admin operations already exist** in [src/cryptic_mcp_admin_handler.erl](../src/cryptic_mcp_admin_handler.erl):
  list/get/suspend/revoke/reactivate users, enrollment CRUD, certificate listing/revocation,
  audit log, and `server_log` tail. Today they authenticate via the `X-Admin-GPG-FP` header
  on a localhost-only listener. **We will reuse the underlying backend functions** and put a
  new auth layer in front of them.
- **User/data model** in [src/cryptic_ca_store.erl](../src/cryptic_ca_store.erl) (SQLite via
  `esqlite`): `gpg_identities`, `enrollment_identities`, `certificates`, `audit_log`. Records
  in [include/cryptic_ca.hrl](../include/cryptic_ca.hrl).
- **Enrollment registration** REST handler
  [src/cryptic_ca_admin_handler.erl](../src/cryptic_ca_admin_handler.erl) — `POST
  /ca/v1/admin/register-enrollment` stores an `enrollment_identity` (Ed25519 pubkey + fp +
  username, status `active`).
- **Mobile cert issuance**: [src/cryptic_ca_mobile_handler.erl](../src/cryptic_ca_mobile_handler.erl)
  — `POST /ca/v1/mobile-csr` verifies an Ed25519 envelope and issues an ECDSA P-256 mTLS cert.
- **Enrollment package + QR** currently produced by the `bin/cryptic-onboard` shell tool:
  Argon2id KDF → AES-256-CBC → HMAC-SHA256, rendered to QR via `qrencode`.
- **Listeners** wired up in [src/cryptic_server.erl](../src/cryptic_server.erl) (mTLS 8443 at
  ~L589, localhost MCP at ~L661). Supervision in [src/cryptic_sup.erl](../src/cryptic_sup.erl).
- **Logging**: [src/cryptic_file_logger.erl](../src/cryptic_file_logger.erl) writes
  `logs/server.log` via `gen_event` ([src/cryptic_event_manager.erl](../src/cryptic_event_manager.erl)).

## 4. Target architecture

```
Browser (HTML + vanilla JS from priv/webadmin/)
        │  HTTPS (server cert, no client cert)  ── port 8444
        ▼
cryptic_webadmin_listener (Cowboy)
   ├── cryptic_webadmin_static        GET  /                (login + SPA shell, assets)
   ├── cryptic_webadmin_auth_handler  POST /admin/api/login, /logout, GET /session
   ├── cryptic_webadmin_api_handler   GET/POST /admin/api/...  (users, enrollments, certs, audit)
   ├── cryptic_webadmin_enroll_handler POST /admin/api/enrollments  (+ QR/package build)
   └── cryptic_webadmin_log_ws        GET  /admin/api/logs/stream  (WebSocket live tail)
        │
        ▼  (shared backend, no logic duplication)
cryptic_admin_core  ──►  cryptic_ca_store / ETS / cryptic_ca_cert / audit_log
cryptic_admin_auth  ──►  admin_accounts table + cryptic_admin_session (ETS)
cryptic_enrollment_pkg ──► Argon2id + AES-256-CBC + HMAC (port of cryptic-onboard, in Erlang)
```

**Key principle:** extract the reusable admin operations that currently live inside
`cryptic_mcp_admin_handler` into a transport-agnostic `cryptic_admin_core` module, then have
both the MCP handler and the new web handlers call it. This avoids duplicating business logic.

## 5. Work breakdown

### Phase 0 — Foundations
- [x] Confirm target OTP version and verify `crypto:pbkdf2_hmac/5` availability (OTP 28.1;
      PBKDF2-HMAC-SHA256 for the admin password hash — built in, no new deps).
- [x] Add `admin_accounts` table + schema migration in `cryptic_ca_store`:
      `username TEXT PRIMARY KEY, pw_hash BLOB, pw_salt BLOB, pw_algo TEXT, kdf_params TEXT,
       status TEXT CHECK(status IN ('active','suspended')), must_change_password INTEGER,
       created_at INTEGER, last_login INTEGER`. Also added the `admin_account` record
      (`include/cryptic_ca.hrl`), `idx_admin_status` index, and 8 store CRUD functions
      (insert/get/list/count/update_password/update_status/update_last_login/delete).
- [ ] CLI/bootstrap command to create the first admin account (`cryptic-onboard create-admin`
      or an Erlang function `cryptic_admin_auth:create_account/2`).
      → **Moved to Phase 1** (depends on the `cryptic_admin_auth` hashing module).

### Phase 1 — Auth & session
- [x] `cryptic_admin_auth`: `create_account/2,3`, `verify_password/2`, `set_password/2`.
      PBKDF2-HMAC-SHA256 (210k iters, 32-byte key, 16-byte per-account salt), constant-time
      compare, dummy-derive on unknown user to level timing. Reads `ca_db_ref` app env.
- [x] `cryptic_admin_session`: gen_server owning a public ETS table; HMAC-SHA256 signed
      cookie (per-boot secret via `persistent_term`, sessions dropped on restart), `HttpOnly`/
      `Secure`/`SameSite=Strict` set by the handler; absolute TTL (`webadmin_session_ttl`, 12h)
      + sliding idle timeout (`webadmin_session_idle`, 30m); CSRF token issued at login.
      Registered in `cryptic_sup`.
- [x] `cryptic_webadmin_auth_handler`: `POST /admin/api/login`, `POST /admin/api/logout`,
      `GET /admin/api/session`. Per-IP login rate limit via `cryptic_ca_rate_limiter`
      (`admin_login` policy = 10/5min). Operation selected by route `State`. CSRF enforced
      on logout. Routes to be wired in Phase 2.
- [x] Bootstrap: `cryptic_rpc:create_admin/2,3` + `count_admins/0` (remsh/`rpc:call`).
      Env-var/container seeding remains Phase 6.

### Phase 2 — Listener & static shell
- [x] `start_webadmin_https/1` in `cryptic_server` (mirrors `start_mcp_localhost_tcp` but
      `cowboy:start_tls`, server cert only, no `cacertfile`, no `verify_peer`; TLS 1.2/1.3;
      listener `cryptic_webadmin_listener`; port from `CRYPTIC_WEBADMIN_PORT` env or config).
      Config: `webadmin_enabled`, `webadmin_port` (8444), cert/key reuse via
      `cryptic_lib:get_server_file/2` from server config. Function kept internal (not exported).
- [x] Route table + `cowboy_static` for `priv/webadmin/` assets and the SPA shell.
      Order: `/admin/api/{login,logout,session}` → `cryptic_webadmin_auth_handler`, then
      `/admin` + `/admin/` → `priv_file webadmin/index.html`, then `/admin/[...]` →
      `priv_dir cryptic webadmin` catch-all for `app.js`/`style.css`.
- [x] Wire into supervision/startup; add `sys.config` keys. Startup gated on `webadmin_enabled`
      in `continue/1` after the MCP block. Added `webadmin_enabled` (false), `webadmin_port`
      (8444), `webadmin_session_ttl` (43200), `webadmin_session_idle` (1800) to `sys.config`.
- [x] Minimal `priv/webadmin/index.html` + `app.js` + `style.css`: login screen, top nav,
      Users / Enrollments / Logs sections. `app.js` runs the full auth flow (session check on
      load, login, logout, section nav) and sends `X-CSRF-Token` on all state-changing calls
      with `credentials: 'same-origin'`. Section bodies are Phase 3/4/5 placeholders.


### Phase 3 — User administration API + UI
- [x] Extract `cryptic_admin_core` (list_users, get_user_info, list_certificates,
      suspend/revoke/reactivate user, list/get enrollments, audit, server_status) from the
      MCP handler. Transport-agnostic (`{ok, Data} | {error, Reason}`, no Cowboy/HTTP);
      mutations take an `ActorId` + `Ip` and write the audit entry internally. The MCP handler
      now delegates all these ops to the core and keeps only its verbose response envelopes;
      the ~16 duplicated helper functions were removed (build is `warnings_as_errors`).
- [x] `cryptic_webadmin_api_handler` (session + CSRF authenticated) exposing:
      `GET /admin/api/users`, `GET /admin/api/users/:fp`, `GET /admin/api/users/:fp/certs`,
      `POST /admin/api/users/:fp/{suspend|reactivate|revoke}`,
      `GET /admin/api/enrollments`, `GET /admin/api/enrollments/:fp`,
      `GET /admin/api/audit`, `GET /admin/api/status`. Validates the session cookie on every
      request, enforces `X-CSRF-Token` (constant-time) on mutations, emits clean REST JSON
      (not MCP envelopes). Mutation `ActorId` = session username; `Ip` = peer. Routes wired in
      `start_webadmin_https/1` before the static catch-all (`:fp` bindings; specific routes
      precede parameterised ones).
- [x] UI: users table with status badges (active/suspended/revoked) + online indicator and a
      status filter; detail drawer showing user fields + certificate list with suspend /
      reactivate / revoke action buttons (reason prompt for suspend/revoke, confirm for
      reactivate; revoked is terminal); enrollments table with status filter; audit log view.
      All calls go through the existing `api()` helper (CSRF + `same-origin`); a 401 bounces
      back to login.

### Phase 4 — Mobile enrollment + QR (browser)
- [ ] `cryptic_enrollment_pkg` (Erlang port of `cryptic-onboard` packaging): build payload,
      KDF, AES-256-CBC encrypt, HMAC. Register the `enrollment_identity` server-side
      (reuse `cryptic_ca_store` insert; same path as `register-enrollment`).
- [ ] QR generation (decided: **client-side**): the API returns the encrypted package string;
      the browser renders the QR with a bundled vanilla-JS QR library in `priv/webadmin/vendor/`.
      Keeps the passphrase/package off any extra round-trip and avoids a server `qrencode` dep.
- [ ] `POST /admin/api/enrollments`: input `{username, passphrase, expiry}` → returns package +
      QR payload + enrollment_fp. UI shows the QR, copy-to-clipboard, and expiry.

### Phase 5 — Log monitoring
- [ ] `cryptic_webadmin_log_ws` WebSocket: on connect, send last N lines, then stream new
      appends (file poll/`inotify`-style tail, or subscribe to the log `gen_event`).
- [ ] `GET /admin/api/logs?offset=&limit=` for paged history + level filter.
- [ ] UI: auto-scrolling live log pane, pause/resume, level filter, search box.

### Phase 6 — Containerization & first-run bootstrap
- [ ] **Drop GPG from the image**: remove `gnupg` from the runtime stage and the
      `${HOME}/.gnupg` bind mounts from `docker-compose.yml`; remove the bootstrap-GPG
      requirement from the entrypoint. (Server auth for mobile users is now Ed25519
      enrollment; the old GPG registration path is deprecated — see §9.)
- [ ] **Auto-provision certs on first run**: entrypoint generates the CA + server certs via
      `generate-mtls-certs.sh` if none are present, instead of hard-failing. Persist to the
      mounted `server_data` volume so restarts are idempotent.
- [ ] **Seed the initial admin**: entrypoint calls the admin-create command exactly once
      (idempotent) from env/secret input — see §7.3 and §9 for the exact contract.
- [ ] Expose the web admin port (default 8444) in `Dockerfile`/`docker-compose.yml`; add
      `webadmin_enabled`/`webadmin_port` env plumbing; extend the healthcheck.
- [ ] Verify the image runs identically under **Podman** (rootless: uid mapping, volume
      perms, `:Z` SELinux label note in docs).

### Phase 7 — Hardening & docs
- [ ] Security review: TLS config, cookie flags, CSRF, login rate-limiting, audit-log every
      admin action (who/what/when), input validation, no secrets in logs.
- [ ] Tests: EUnit for auth/session/core, Lux end-to-end for login → user action → enrollment;
      a container smoke test (boot fresh image → auto-certs → seed admin → log in → create
      enrollment).
- [ ] Docs: `docs/WEB-ADMIN.md` operator guide; update `docs/DOCKER.md` for the GPG-free flow
      and admin bootstrap; note deprecation path for MCP/CLI overlap.

## 6. Security considerations

- Password hashing with per-user salt; constant-time verification; configurable KDF params.
- Session cookies: `Secure`, `HttpOnly`, `SameSite=Strict`; server-side session store with TTL.
- CSRF protection on all state-changing endpoints (double-submit token).
- Login brute-force protection via `cryptic_ca_rate_limiter`.
- The admin listener is server-cert TLS only — **do not** expose it publicly without a firewall;
  document binding to a management interface/VPN.
- Every admin action writes an `audit_log` entry with the acting admin account.
- Enrollment passphrase handling: never logged; package returned once and not persisted.
- **Container bootstrap secrets**: prefer a mounted **password-hash file / Docker–Podman
  secret** over a plaintext `CRYPTIC_ADMIN_PASSWORD` env var (env vars leak via `inspect`,
  `/proc`, and logs). If a plaintext password is supplied, force a password change on first
  login and never echo it. Admin seeding is **idempotent** — it must not overwrite an existing
  account or reset its password on container restart.

## 7. Resolved decisions (previously open questions)

1. **Password hashing** — Use **PBKDF2-HMAC-SHA256** via the built-in `crypto:pbkdf2_hmac/5`.
   No new dependency, no shell-out. Per-user random salt, high iteration count, constant-time
   compare. (Argon2 rejected for v1 to avoid a runtime binary/NIF dependency.)
2. **QR rendering** — **Client-side** using a small bundled vanilla-JS QR library in
   `priv/webadmin/vendor/`. Keeps the enrollment passphrase/package off extra round-trips and
   avoids a server-side `qrencode` system dependency. The API returns the encrypted package
   payload; the browser renders the QR.
3. **First-admin bootstrap** — A **CLI/Erlang command** creates the first admin account
   (e.g. `cryptic_admin_auth:create_account/2`, optionally surfaced via `cryptic-onboard
   create-admin`). No unauthenticated web setup endpoint is ever exposed. **In containers**
   the entrypoint invokes this command once at first boot from configuration/secrets (see §9);
   the operation is idempotent so restarts never clobber or reset the account.
4. **MCP endpoint** — **Keep it running alongside** the web admin during transition. Both call
   the shared `cryptic_admin_core`, so there is no logic duplication; existing MCP/LLM
   workflows keep working. Deprecate later once the web admin covers all use cases.
5. **Admin roles** — **Single full-admin role for v1.** Read-only vs full roles are deferred
   until there is a concrete need (schema/UI/enforcement complexity not justified yet).

## 8. Suggested new modules / files

| File | Purpose |
|------|---------|
| `src/cryptic_admin_core.erl` | Transport-agnostic admin operations (shared by MCP + web) |
| `src/cryptic_admin_auth.erl` | Admin account creation + password verification |
| `src/cryptic_admin_session.erl` | Session store + cookie signing/CSRF |
| `src/cryptic_webadmin_auth_handler.erl` | login/logout/session endpoints |
| `src/cryptic_webadmin_api_handler.erl` | users / enrollments / certs / audit / status API |
| `src/cryptic_webadmin_enroll_handler.erl` | enrollment package + QR generation |
| `src/cryptic_webadmin_log_ws.erl` | live log WebSocket |
| `src/cryptic_enrollment_pkg.erl` | Erlang port of `cryptic-onboard` packaging |
| `priv/webadmin/` | `index.html`, `app.js`, `style.css`, `vendor/` |
| `docs/WEB-ADMIN.md` | operator guide |
| schema migration in `src/cryptic_ca_store.erl` | `admin_accounts` table |
| `scripts/docker-entrypoint.sh` (edit) | auto-provision certs, seed admin, drop GPG checks |
| `Dockerfile` / `docker-compose.yml` (edit) | remove `gnupg` + `.gnupg` mounts, expose 8444 |

## 9. Container packaging & initial admin bootstrap

### 9.1 What changes vs today
The current image (`Dockerfile`, `docker-compose.yml`) installs `gnupg`, bind-mounts the host
`~/.gnupg` into both server and client, ships bootstrap GPG keys under
`priv/ca/bootstrap/*.gpg`, and **hard-fails** if CA certs are missing. With Ed25519 enrollment
replacing GPG registration, we can:

- Remove `gnupg` from the runtime image and delete the `~/.gnupg` mounts.
- Stop requiring bootstrap GPG keys; the GPG registration REST path is deprecated (§ below).
- Turn cert provisioning into an automatic first-run step instead of a manual pre-step.

### 9.2 First-boot sequence (entrypoint)
1. Ensure `server_data` layout exists (already done).
2. If CA/server certs are absent → generate them via `generate-mtls-certs.sh` and persist to
   the volume. If present → use them. (Idempotent.)
3. **Seed admin (idempotent):** if no admin account exists, create one from the first
   available source, in priority order:
   - `CRYPTIC_ADMIN_PASSWORD_HASH_FILE` — path to a mounted secret containing a
     pre-computed PBKDF2 hash record (**preferred**; no plaintext ever in the container).
   - `CRYPTIC_ADMIN_PASSWORD_FILE` — path to a mounted secret with a plaintext password;
     hashed at boot, then the account is flagged `must_change_password`.
   - `CRYPTIC_ADMIN_PASSWORD` — plaintext env var (**discouraged**; same must-change flag).
   - none provided → generate a random password, create the account flagged
     `must_change_password`, and print it **once** to the container log for the operator.
   Username from `CRYPTIC_ADMIN_USER` (default `admin`).
4. Start the server (web admin listener on `webadmin_port`).

### 9.3 Bootstrap contract (env / secrets)
| Variable | Meaning | Notes |
|----------|---------|-------|
| `CRYPTIC_ADMIN_USER` | initial admin username | default `admin` |
| `CRYPTIC_ADMIN_PASSWORD_HASH_FILE` | file with precomputed PBKDF2 record | preferred |
| `CRYPTIC_ADMIN_PASSWORD_FILE` | file with plaintext password | Docker/Podman secret |
| `CRYPTIC_ADMIN_PASSWORD` | plaintext password | discouraged; forces change |
| `CRYPTIC_WEBADMIN_PORT` | web admin port | default 8444 |

Provide a helper (`cryptic-onboard hash-admin-password` or an escript) so operators can
generate the hash record offline for the `*_HASH_FILE` path.

### 9.4 GPG deprecation note
The GPG-based registration flow (`/ca/v1/register-gpg`, `cryptic_ca_gpg`, `erl_gpg`,
bootstrap keys) becomes **legacy**. It stays compilable for existing deployments but is no
longer part of the container happy path or documented setup. A follow-up can fully remove
`erl_gpg`/`gnupg` once no deployment depends on it.
