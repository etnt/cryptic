# Overview

**Goal:** A small, encrypted chat service in Erlang for friends & family that is simple, private, and maintainable. 

**Core properties:** 
- End-to-end encryption (E2EE)
- User authentication
- Message delivery (online + store-and-forward)
- Presence
- Optional group chat

**Focus:** Correctness and safety over feature bloat.

## Architecture (High-Level)

- **Clients:** Lightweight Erlang (or mobile/web) clients that hold users' private keys
- **Server(s):** Erlang/OTP cluster responsible for message routing, presence, and optional encrypted message storage. Server never has plaintext messages
- **Key management:** Clients generate and store identity keypairs locally. Server only stores public keys and metadata
- **Transport:** TLS for client-server channel metadata + delivery; messages themselves are encrypted E2EE
- **Storage:** Encrypted blobs (opaque to server) if offline messages need persistence
- **Optional components:** Push notification gateway, web client, admin console

## Components & Responsibilities

### Client
- Generate and persist identity keypair (long-term) — e.g., X25519/Ed25519
- Generate ephemeral session keys per conversation (for forward secrecy)
- Implement E2EE protocol (message encryption, signing, ratchet/handshake)
- Handle registration/login (prove identity to server)
- Maintain local encrypted message history and key storage
- UI: simple chat list, conversation view, contact verification UI (safety numbers / QR)

### Server (Erlang/OTP)
- **Authentication service:** Accept client registrations, store username → public keys
- **Presence service:** Track online status, route presence events
- **Delivery broker:** Route encrypted message blobs to recipients; store blobs for offline users (encrypted)
- **User directory API:** Let clients fetch public keys and safety fingerprint metadata
- **Optional push gateway:** Notify mobile clients of pending messages
- **Admin/metrics endpoints:** No access to plaintext

### Persistence
- Store public keys, metadata, and encrypted message blobs
- Use a simple DB (Postgres or Mnesia for pure Erlang). Keep blobs opaque
- Backups encrypted at rest

### Networking & Protocols
- **Transport:** TLS (mutual TLS optional) for client ↔ server channel
- **Application protocol:** JSON or compact binary (CBOR/MessagePack) for metadata; message payload is binary encrypted blob
- **Real-time delivery:** WebSocket or long-poll for real-time delivery; fallback to polling for simple clients

### Cryptography Primitives & E2EE Protocol
- **Primitives:** X25519 for key agreement, Ed25519 for signatures, AES-256-GCM or ChaCha20-Poly1305 for AEAD
- **Protocol options:**
  - Use the Double Ratchet algorithm (Signal protocol) for 1:1 chats, OR
  - Use Olm/Megolm for group chat, OR
  - **Preferred:** Implement X3DH + Double Ratchet (for forward secrecy and future compatibility)
- **Key verification:** Safety numbers, QR scanning, manual fingerprint compare
- **Privacy:** Protect against metadata leakage where feasible (timing obfuscation, padded message sizes optional)

## Data Model (Conceptual)

### User
- `user_id`: Unique identifier
- `username`: Display name
- `public_identity_key`: Ed25519 public key
- `public_prekey`: X25519 public key
- `prekey_bundle_metadata`: Associated metadata

### Conversation
- `convo_id`: Unique conversation identifier
- `member_list`: List of participants (for group chats)
- `type`: Conversation type (1:1/group)

### Message Blob
- `sender_id`: Message sender identifier
- `recipient_id/convo_id`: Target recipient or conversation
- `timestamp`: Message timestamp
- `encrypted_payload`: Opaque encrypted content
- `signature`: Optional message signature
- `delivery_status`: Current delivery state

## Sequence Flows (Key Flows)

### Registration
1. Client generates identity keypair + prekeys
2. Client TLS connects to server, sends username + public identity key + prekeys (signed)
3. Server stores public info and responds OK

### Establishing 1:1 Conversation (X3DH + Double Ratchet)
1. Client A fetches B's prekey bundle from server
2. Client A performs X3DH handshake to derive shared secret, starts double ratchet
3. Client A sends first encrypted message blob to server for B
4. Server routes/stores blob. B receives and continues ratchet

### Message Send/Delivery
1. Client encrypts message with current ratchet key → AEAD ciphertext
2. Send over TLS to server with recipient ID
3. Server routes immediately if recipient online; otherwise store encrypted blob for delivery on next connect

### Offline & Sync
1. Server keeps encrypted blobs until delivered or TTL expires
2. When client reconnects, it pulls pending blobs and processes locally

### Group Chat (Simpler Approaches)
- **Option 1:** Use pairwise Double Ratchet per member (inefficient but simple)
- **Option 2:** Adopt group ratchet (Megolm)
  - Sender encrypts message once to group symmetric key
  - Distribute group session keys using pairwise E2EE during membership changes

## Erlang/OTP Design Details

### Supervisor Architecture
- **Supervisor tree:** Top-level supervisor → apps: `auth_sup`, `presence_sup`, `delivery_sup`, `storage_sup`, `http_ws_sup`
- **Presence:** GenServer per user to track connections and subscriptions
- **Delivery broker:** `persistent_queue` process per user/conversation to queue encrypted blobs
- **Connection handlers:** Cowboy (HTTP/WS) or Ranch sockets for TLS + WebSocket
- **Concurrency:** Rely on Erlang lightweight processes for each connection and conversation state

### Persistence Options
- **Postgres:** For durability + SQL queries
- **Mnesia:** For pure Erlang distributed DB (note: Mnesia has limits for large blobs)

### API Design
- **REST/HTTP API:** Registration, public key discovery, admin endpoints
- **WebSocket:** Real-time message exchange and presence updates

## Security & Privacy Considerations

### Client-Side Security
- **Key storage:** Encrypted with passphrase and OS secure store where available
- **Private keys:** Never leave client devices

### Server-Side Security
- **No plaintext access:** Never log plaintext messages or keys on server. Treat blobs as opaque
- **Secure randomness:** Use secure random for keys and nonces
- **Replay protection:** Implement replay protection and message sequence numbers
- **Rate limiting:** Rate-limit and throttle to prevent abuse

### Privacy Protection
- **Metadata minimization:** Avoid storing who talks to whom if possible. If impossible, minimize retention
- **Key rotation:** Plan for key rotation and account recovery carefully (account recovery risks E2EE if server can re-encrypt)

### Infrastructure Security
- **TLS everywhere:** All communications over TLS
- **Strong configuration:** Use strong TLS configuration and modern cipher suites

## Deployment & Operations

### Scaling Strategy
- Start single server node for early testing
- Design for horizontal scaling using external DB and stateless routing when possible

### Infrastructure
- **TLS certificates:** Use Let's Encrypt and strong TLS configuration
- **Backups:** Encrypted DB backups with key rotation
- **Monitoring:** Minimal metrics (uptime, queue lengths), alerting on failure

### Testing Strategy
- **Unit tests:** Protocol implementation
- **Property tests:** Concurrency scenarios
- **Fuzz tests:** Crypto input validation
- **End-to-end tests:** Multiple client scenarios

## Implementation Roadmap (Milestones)

### Phase 1: Prototype MVP
- Minimal client CLI (Erlang) + simple server
- Basic functionality: register, public key fetch, send/receive encrypted blobs using pre-shared keys
- Simplified prekey handshake
- WebSocket + TLS and DB for public keys + blob storage

### Phase 2: Add Proper E2EE
- Implement X3DH handshake + Double Ratchet for 1:1 chat
- Add key verification UI/CLI
- Implement safety numbers and key fingerprinting

### Phase 3: Improve UX & Features
- Presence system
- Delivery receipts
- Offline storage
- Message history sync
- Optional group chat (Megolm or per-recipient encryption)

### Phase 4: Hardening & Launch
- Security audit of crypto implementation (prefer using well-tested libraries or bindings)
- Deployment automation
- Backup systems
- Monitoring and alerting

## Libraries & References (Implementation Aids)

### Cryptography
- **Crypto primitives:** libsodium (via Erlang NIF or bindings) for X25519/Ed25519/ChaCha20-Poly1305

### Erlang Web Stack
- **HTTP/WebSocket:** Cowboy, Ranch
- **Alternative:** Plug/Cowboy or Phoenix channels for faster development

### Database Options
- **PostgreSQL:** epgsql or Ecto-like wrapper
- **Pure Erlang:** Mnesia for in-memory/distributed use

### E2EE Protocol References
- **Signal:** X3DH, Double Ratchet specifications
- **Matrix:** Olm/Megolm implementation guides

## Minimal Security Checklist Before Sharing with Others

- [ ] Clients verify each other's identity keys (safety numbers)
- [ ] Use audited crypto libraries, avoid custom crypto
- [ ] Private keys never leave client devices
- [ ] Server stores only public keys + encrypted blobs
- [ ] TLS everywhere
- [ ] Rate limits and abuse controls implemented
