# Overview
Goal: a small, encrypted chat service in Erlang for friends & family that is simple, private, and maintainable. Core properties: end-to-end encryption (E2EE), user authentication, message delivery (online + store-and-forward), presence, and optional group chat. Focus on correctness and safety over feature bloat.

## Architecture (high-level)
Clients: lightweight Erlang (or mobile/web) clients that hold users' private keys.
Server(s): Erlang/OTP cluster responsible for message routing, presence, and optional encrypted message storage. Server never has plaintext messages.
Key management: clients generate and store identity keypairs locally. Server only stores public keys and metadata.
Transport: TLS for client-server channel metadata + delivery; messages themselves are encrypted E2EE.
Storage: encrypted blobs (opaque to server) if offline messages need persistence.
Optional components: push notification gateway, web client, admin console.

##Components & responsibilities
Client
Generate and persist identity keypair (long-term) — e.g., X25519/Ed25519.
Generate ephemeral session keys per conversation (for forward secrecy).
Implement E2EE protocol (message encryption, signing, ratchet/handshake).
Handle registration/login (prove identity to server).
Maintain local encrypted message history and key storage.
UI: simple chat list, conversation view, contact verification UI (safety numbers / QR).
Server (Erlang/OTP)
Authentication service: accept client registrations, store username → public keys.
Presence service: track online status, route presence events.
Delivery broker: route encrypted message blobs to recipients; store blobs for offline users (encrypted).
User directory API: let clients fetch public keys and safety fingerprint metadata.
Optional push gateway: notify mobile clients of pending messages.
Admin/metrics endpoints (no access to plaintext).
Persistence
Store public keys, metadata, and encrypted message blobs.
Use a simple DB (Postgres or Mnesia for pure Erlang). Keep blobs opaque.
Backups encrypted at rest.
Networking & protocols
Transport: TLS (mutual TLS optional) for client ↔ server channel.
Application protocol: JSON or compact binary (CBOR/MessagePack) for metadata; message payload is binary encrypted blob.
Use WebSocket or long-poll for real-time delivery; fallback to polling for simple clients.
Cryptography primitives & E2EE protocol
Use modern primitives: X25519 for key agreement, Ed25519 for signatures, AES-256-GCM or ChaCha20-Poly1305 for AEAD.
Implement an established E2EE pattern rather than inventing one: either
Use the Double Ratchet algorithm (Signal protocol) for 1:1 chats, or
Use Olm/Megolm for group chat, or
Simpler: implement X3DH + Double Ratchet (preferred for forward secrecy and future compatibility).
Include key verification (safety numbers, QR scanning, manual fingerprint compare).
Protect against metadata leakage where feasible (timing obfuscation, padded message sizes optional).

## Data model (conceptual)
User:
user_id, username, public_identity_key (Ed25519), public_prekey (X25519), prekey bundle metadata
Conversation:
convo_id, member list (for group), type (1:1/group)
Message blob:
sender_id, recipient_id/convo_id, timestamp, encrypted_payload (opaque), signature (if applicable), delivery_status

## Sequence flows (key flows)
Registration
Client generates identity keypair + prekeys.
Client TLS connects to server, sends username + public identity key + prekeys (signed).
Server stores public info and responds OK.
Establishing 1:1 conversation (X3DH + Double Ratchet)
Client A fetches B's prekey bundle (from server), performs X3DH handshake to derive shared secret, starts double ratchet.
Client A sends first encrypted message blob to server for B.
Server routes/stores blob. B receives and continues ratchet.
Message send/delivery
Client encrypts message with current ratchet key → AEAD ciphertext.
Send over TLS to server with recipient id.
Server routes immediately if recipient online; otherwise store encrypted blob for delivery on next connect.
Offline & sync
Server keeps encrypted blobs until delivered or TTL expires.
When client reconnects, it pulls pending blobs and processes locally.
Group chat (simpler approaches)
Use pairwise Double Ratchet per member (inefficient but simple) OR adopt group ratchet (Megolm).
Sender encrypts message once to group symmetric key; distribute group session keys using pairwise E2EE during membership changes.

## Erlang/OTP design details
Use supervisors and GenServers/GenStateMachines:
Supervisor tree: top-level supervisor → apps: auth_sup, presence_sup, delivery_sup, storage_sup, http_ws_sup.
Presence: GenServer per user to track connections and subscriptions.
Delivery broker: persistent_queue process per user/convo to queue encrypted blobs.
Connection handlers: Cowboy (HTTP/WS) or Ranch sockets for TLS + WebSocket.
Concurrency: rely on Erlang lightweight processes for each connection and conversation state.
Persistence:
Use Postgres for durability + SQL queries, or Mnesia if you want pure Erlang distributed DB (Mnesia limits for large blobs).
API:
REST/HTTP API for registration, public key discovery, admin.
WebSocket for real-time message exchange and presence.

## Security & privacy considerations
Client-side key storage: encrypted with passphrase and OS secure store where available.
Never log plaintext messages or keys on server. Treat blobs as opaque.
Use secure random for keys and nonces.
Implement replay protection and message sequence numbers.
Rate-limit and throttle to prevent abuse.
Consider metadata minimization: avoid storing who talks to whom if possible. If impossible, minimize retention.
Plan for key rotation and account recovery carefully (account recovery risks E2EE if server can re-encrypt).

## Deployment & ops
Start single server node for early testing; design for horizontal scaling using an external DB and stateless routing when possible.
Use TLS certs (Let's Encrypt) and strong TLS configuration.
Backups: encrypted DB backups; rotate keys.
Monitoring: minimal metrics (uptime, queue lengths), alerting on failure.
Testing: unit tests for protocol, property tests for concurrency, fuzz tests for crypto inputs, end-to-end tests with multiple clients.

## Implementation roadmap (milestones)
Prototype MVP
Minimal client CLI (Erlang) + simple server: register, public key fetch, send/receive encrypted blobs using pre-shared keys (prekey handshake simplified).
Use WS + TLS and DB for public keys + blob storage.
Add proper E2EE
Implement X3DH handshake + Double Ratchet for 1:1 chat.
Add key verification UI/CLI.
Improve UX & features
Presence, delivery receipts, offline storage, message history sync.
Optional group chat (Megolm or per-recipient encryption).
Hardening & launch
Security audit of crypto implementation (prefer using well-tested libraries or bindings).
Deployment automation, backups, monitoring.

## Libraries & references (implementation aids)
Crypto primitives: libsodium (via Erlang NIF or bindings) for X25519/Ed25519/ChaCha20-Poly1305.
Erlang web stack: Cowboy (HTTP/WS), Ranch, Plug/Cowboy or Phoenix channels if you want faster development.
DB: Postgres + epgsql or Ecto-like wrapper; or Mnesia for in-memory/distributed use.
E2EE protocol references: Signal (X3DH, Double Ratchet), Olm/Megolm (Matrix).

## Minimal security checklist before sharing with others
Clients verify each other's identity keys (safety numbers).
Use audited crypto libraries, avoid custom crypto.
Private keys never leave client devices.
Server stores only public keys + encrypted blobs.
TLS everywhere.
Rate limits and abuse controls.
