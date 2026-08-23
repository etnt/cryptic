# Cryptic Web Administration — Implementation Plan

> Status: **Draft for review**
> Scope: A browser-based admin console for the Cryptic server, replacing/augmenting the
> existing Erlang shell (`cryptic_admin`), MCP admin endpoint, and `cryptic-onboard` CLI.

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

## 2. Confirmed design decisions

| Area | Decision |
|------|----------|
| Auth model | New `admin_accounts` table (username + **Argon2id** password hash) + signed, HTTP-only session cookie. Decoupled from GPG identities. |
| Frontend | Server-rendered HTML shell + **vanilla JS**, talking to a JSON API. Served from `priv/webadmin/`. **No Node/build step.** |
| Transport | **New dedicated HTTPS listener** on a separate admin port (default **8444**), server-cert TLS, **no client cert required**. Isolated from the 8443 mTLS messaging listener and the 8081 localhost MCP endpoint. |
| Log streaming | Live tail via **WebSocket** + paged historical view over the JSON API. |

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
- [ ] Confirm target OTP version and verify `crypto:pbkdf2_hmac/5` availability (decided:
      PBKDF2-HMAC-SHA256 for the admin password hash — built in, no new deps).
- [ ] Add `admin_accounts` table + schema migration in `cryptic_ca_store`:
      `username TEXT PRIMARY KEY, pw_hash BLOB, pw_salt BLOB, pw_algo TEXT, kdf_params TEXT,
       created_at INTEGER, last_login INTEGER, status TEXT`.
- [ ] CLI/bootstrap command to create the first admin account (`cryptic-onboard create-admin`
      or an Erlang function `cryptic_admin_auth:create_account/2`).

### Phase 1 — Auth & session
- [ ] `cryptic_admin_auth`: `create_account/2`, `verify_password/2`, `set_password/2`.
      Constant-time compare; per-account random salt.
- [ ] `cryptic_admin_session`: ETS-backed sessions with signed, HTTP-only, `Secure`,
      `SameSite=Strict` cookies; TTL + idle timeout; CSRF token issued at login.
- [ ] `cryptic_webadmin_auth_handler`: `POST /admin/api/login`, `POST /admin/api/logout`,
      `GET /admin/api/session`. Rate-limit login attempts (reuse `cryptic_ca_rate_limiter`).

### Phase 2 — Listener & static shell
- [ ] `start_webadmin_https/1` in `cryptic_server` (mirrors `start_mcp_localhost_tcp` but
      `cowboy:start_tls`, server cert only, `fail_if_no_peer_cert=false`, no `verify_peer`).
      Config: `webadmin_enabled`, `webadmin_port` (8444), cert/key reuse from server config.
- [ ] Route table + `cowboy_static` for `priv/webadmin/` assets and the SPA shell.
- [ ] Wire into supervision/startup; add `sys.config` keys.
- [ ] Minimal `priv/webadmin/index.html` + `app.js` + `style.css`: login screen, top nav,
      Users / Enrollments / Logs sections. All API calls send the CSRF header.

### Phase 3 — User administration API + UI
- [ ] Extract `cryptic_admin_core` (list_users, get_user_info, list_certificates,
      suspend/revoke/reactivate user, list/get enrollments, audit) from the MCP handler.
- [ ] `cryptic_webadmin_api_handler` (session-authenticated) exposing:
      `GET /admin/api/users`, `GET /admin/api/users/:fp`, `GET /admin/api/users/:fp/certs`,
      `POST /admin/api/users/:fp/{suspend|reactivate|revoke}`,
      `GET /admin/api/enrollments`, `GET /admin/api/audit`, `GET /admin/api/status`.
- [ ] UI: users table with status badges + online indicator, detail drawer, action buttons
      with confirm dialogs, audit log view.

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

### Phase 6 — Hardening & docs
- [ ] Security review: TLS config, cookie flags, CSRF, login rate-limiting, audit-log every
      admin action (who/what/when), input validation, no secrets in logs.
- [ ] Tests: EUnit for auth/session/core, Lux end-to-end for login → user action → enrollment.
- [ ] Docs: `docs/WEB-ADMIN.md` operator guide; note deprecation path for MCP/CLI overlap.

## 6. Security considerations

- Password hashing with per-user salt; constant-time verification; configurable KDF params.
- Session cookies: `Secure`, `HttpOnly`, `SameSite=Strict`; server-side session store with TTL.
- CSRF protection on all state-changing endpoints (double-submit token).
- Login brute-force protection via `cryptic_ca_rate_limiter`.
- The admin listener is server-cert TLS only — **do not** expose it publicly without a firewall;
  document binding to a management interface/VPN.
- Every admin action writes an `audit_log` entry with the acting admin account.
- Enrollment passphrase handling: never logged; package returned once and not persisted.

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
   create-admin`). No unauthenticated web setup endpoint is ever exposed.
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
```
