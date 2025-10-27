# NAMING AND ADDRESSING SCHEME
> Preserves privacy, supports federation, and remains compatible
> with Signal-style cryptography.

## Why addressing matters

The choice of addressing model determines:

| Goal | Implication |
|------|-------------|
| Privacy | How much identifying information (e.g., usernames, phone numbers) is exposed to the network |
| Federation | How clients discover and contact users across servers |
| Trust boundaries | Which entities can link user IDs, keys, or metadata |
| Usability | Whether people can easily find each other and communicate |

* Signal chose phone numbers for simplicity but lost anonymity.
* Matrix chose user IDs tied to domains for federation but leaks some metadata.
* Cryptic have an opportunity to combine the good parts of both — privacy
  by design with federated reachability.

## Identity layers in your system

You can think of three layers of identity:

| Layer | Purpose | Visibility |
|-------|---------|------------|
| Long-term identity key | Root cryptographic identity (Curve25519 keypair) | Never shared directly; used for signatures |
| Routing address | How messages find a user on a server | Visible to the network, but pseudonymous |
| Display name / contact info | Human-friendly, optional | Shared voluntarily (like QR codes or invitations) |

Separating these layers lets you provide both privacy and usability.

## Designing a federated addressing scheme

Combine federated pseudonyms with ephemeral sub-addresses:

1. Each user has a long-term pseudonymous ID:

    @5d8f9b2c:relay.net

2 For each new contact or conversation, the client derives a unique sub-address:

    @5d8f9b2c+7af3c:relay.net

  * The suffix is derived from a hash of the peer’s identity key.
  * This prevents linkability between conversations.

3. The server only knows these sub-addresses, not which ones belong to the same user.

Pros:
  * Federated and routable.
  * Still unlinkable across contacts.
  * Allows simple lookups and push notifications.

**Implementation idea:**
Store each sub-address as a separate “mailbox” entry on the server, with an
expiry timer and optional quota.

## Metadata-resilient lookup

To make discovery private, you can implement a Private Contact Discovery
service, similar to Signal’s design:

  * Use private set intersection (PSI) or hashed identifiers.
  * Allow users to see which contacts are reachable without revealing their address book.
  * This could run per-server, so each federated node handles its own discovery.

Alternatively, keep it completely opt-in — people only connect via explicit
exchange (e.g., QR, invite link, contact code).

## Example addressing spec sketch

Here’s a rough conceptual example:
 ```
Identity:
    identity_key: Curve25519 public key
    server_domain: FQDN of chosen server
    base_id: SHA256(identity_key)[:16]   # 16-byte truncated fingerprint

Address:
    user_id = "@" + base32(base_id) + ":" + server_domain
    sub_id = base32(HMAC(identity_key, peer_identity_key))[:8]
    address = user_id + "+" + sub_id
```

Example:

    @A4K7TZGQWPSJ6MZY:relay.example.org+MK92D7QJ

  * The server only sees this opaque string.
  * The peer can verify the binding cryptographically using identity keys.
  * You can rotate or expire sub-addresses for forward secrecy.


## EXAMPLE

Below is a concrete, end-to-end **example protocol flow** showing how Alice
(client on `relay.org`) finds Bob (client on `server.net`), performs **X3DH**
to bootstrap a Double Ratchet session, and then sends encrypted messages via
your lightweight relay servers. I use the **hybrid addressing** idea from
earlier (`@baseid:domain+subid`) and include:

* API endpoints (client→server and optional server→server)
* JSON payload examples
* What the client does cryptographically
* Server behavior, storage layout, and TTLs
* Offline delivery and subsequent messaging
* Key rotation and unlinkability notes

## Notation & primitives

* Identity keypair: `IK` = (Curve25519 keypair; public `IKx`) and a corresponding Ed25519 signing key `SIG` for authenticated bundles (recommended).
* Signed Prekey: `SPK` (longer-lived ephemeral X25519 keypair)
* One-Time Prekeys: `OPK_i` (one-time X25519 keypairs; consumed on use)
* Ephemeral key: `EK` (generated per X3DH initiation)
* `H()` = SHA256, `HMAC(k, m)` = HMAC-SHA256
* Base ID generation: `base_id = base32(H(IKx)[:16])`
* Sub-ID derivation: `sub_id = base32(HMAC(IKx, peer_IKx)[:8])` — deterministic per-peer, unlinkable across peers
* Address format: `@<base_id>:<server.domain>+<sub_id>`

Transport and server assumptions:

* TLS for all client↔server and server↔server connections.
* Servers do **not** decrypt message payloads; they store and forward opaque blobs.
* Servers authenticate prekey bundles by checking a signature by `SIG` over the bundle.


## Server API (Client → Server)

Suggested minimal endpoints (HTTP/REST style):

```http
GET  /.well-known/relay            -> Relay capabilities (optional)
GET  /users/{user_id}/prekey-bundle
POST /users/{user_id}/messages     -> Deliver encrypted envelope to user
GET  /users/{user_id}/pending      -> Pull pending messages
POST /users/{user_id}/prekeys      -> Upload prekeys / bundle (client auth required)
DELETE/PUT /users/{user_id}/prekeys -> manage rotation
```

Optional federation: servers accept `POST /s2s/deliver` from trusted servers with envelopes.


## Server storage schema (per user)

**Server (e.g., `server.net`) stores per base_id:**

```erlang
user {
  base_id: "A4K7TZGQ...",
  server_domain: "server.net",
  identity_pub: <IKx>,         // identity public key
  sig_pub: <SIG_pub>,          // verification key for signature
  signed_bundle: <signature over bundle>,
  signed_bundle_ts: <timestamp>,

  signed_prekey: {spk_pub, spk_id, expiry_ts},
  one_time_prekeys: [{opk_id, opk_pub, consumed=false, uploaded_ts}],
  bundle_ttl: 86400,           // e.g. 24h or server policy
  mailboxes: [{sub_id, queue: [envelope,...], ttl}]
}
```

* Prekey bundles must be signed by the `SIG` key so clients can verify authenticity without contacting another service.
* Servers only store **public** keys and opaque encrypted message envelopes.

**Message envelope** (stored in mailbox):

```json
{
  "from": "@<alice_base>:relay.org+<sub>",
  "to": "@<bob_base>:server.net+<sub>",
  "timestamp": 1660000000,
  "ciphertext": "<base64 of DoubleRatchet ciphertext or X3DH init envelope>",
  "type": "X3DH_INIT" | "MESSAGE",
  "meta": { ... optional routing metadata ... }
}
```

* Servers should enforce TTL and size quotas; expire mailboxes/sub-addresses if unused.


## Creating addresses / sub-addresses (client-side)

When Alice and Bob create accounts:

* On install, client generates `IK` (Curve25519) + `SIG` (Ed25519) and registers with chosen server using `POST /users/{user_id}/prekeys`:

  * The uploaded bundle includes `identity_pub`, `sig_pub`, `signed_prekey`, and a batch of `one_time_prekeys`.
  * Server responds with `user_id` base_id and accepts.

Sub-address for a peer:

```
sub_id = base32(HMAC(IKx_alice, IKx_bob)[:8])
alice_address_for_bob = "@" + base_id_alice + ":" + alice_server + "+" + sub_id
```

* Alice stores Bob’s full address (including his `+subid`), but Bob’s server only sees that subid mailbox; servers cannot trivially link subids across recipients.

## Initial contact (Alice → Bob) when Bob is online or offline

### Step 0 — Alice knows Bob’s address

Alice obtains Bob’s address by:

* Manual exchange (QR, paste)
* Discovery via out-of-band (shared link)
* Optional private discovery PSI (advanced)

Example: `bob_addr = "@B9K2X...:server.net+QW83XZ12"`

### Step 1 — Alice fetches Bob’s prekey bundle

Request:

```
GET https://server.net/users/@B9K2X...:server.net/prekey-bundle?sub=QW83XZ12
```

Response (JSON):

```json
{
  "identity_key": "<base64 IKx>",
  "sig_pub": "<base64 SIG_pub>",
  "signed_prekey": {"id": "spk1", "pub": "<base64 SPK_pub>", "expiry": 1730000000},
  "one_time_prekey": {"id": "opk42", "pub": "<base64 OPK_pub>"},
  "bundle_signature": "<base64 signature>"    // signature by SIG over the whole bundle
}
```

Alice verifies `bundle_signature` using `sig_pub`. If verification fails, abort.

### Step 2 — Alice performs X3DH and prepares initial envelope

Alice (client) chooses an ephemeral `EK`, and performs the X3DH sequence using:

* Alice: IK_A (identity), EK_A (ephemeral)
* Bob: IK_B, SPK_B, OPK_B

Compute X3DH shared secret per spec (X25519 operations). Derive initial root key and ratchet keys. Construct an **X3DH_INIT** envelope that contains the fields needed by Bob to complete the handshake (Alice’s identity pub, ephemeral pub, any signature if desired), but **encrypted** with Bob’s prekey material? (In X3DH initial message the shared secret is used to derive encryption keys; the initial payload contains Alice’s IK and EK in the clear inside the envelope but the envelope's payload must be integrity-protected.)

Simplified envelope JSON:

```json
{
  "type": "X3DH_INIT",
  "from": "@A4K7...:relay.org+S1",
  "to": "@B9K2...:server.net+QW83XZ12",
  "x3dh": {
    "alice_ik": "<base64 IK_A_pub>",
    "alice_ek": "<base64 EK_A_pub>",
    "ek_signature": "<optional signature of EK by SIG_A>",
    "info": "<optional user data: display name>",
    "opk_id_used": "opk42"
  },
  "ciphertext": "<optional application payload, encrypted using X3DH-derived key>",
  "timestamp": 1690000000
}
```

### Step 3 — Alice posts envelope to Bob’s server

```
POST https://server.net/users/@B9K2...:server.net/messages
Body: { envelope }
```

Server behavior:

* Validate `to` format and that `sub_id` mailbox exists (or create ephemeral mailbox).
* Append envelope to Bob's mailbox queue.
* If Bob is online (connected via websocket/push), server pushes a notification (but without revealing plaintext).
* Mark `opk42` as consumed (if used).

### Step 4 — Bob receives and completes X3DH

When Bob’s client pulls `GET /users/{user_id}/pending` or receives push:

* It fetches the envelope and reads `x3dh` header.
* Using its private `SPK` and `OPK` and its `IK`, Bob computes same X3DH shared secret, derives the root key and initializes the Double Ratchet with Alice’s ephemeral key.
* Bob can now decrypt `ciphertext` (the initial application payload).
* Bob may reply with a `X3DH_REPLY` or start sending `MESSAGE` type envelopes encrypted under the ratchet.

Bob should also rotate or mark the OPK consumed in server storage.

## Subsequent messages (Double Ratchet)

Once the Double Ratchet session is established:

* Alice and Bob exchange `MESSAGE` envelopes containing **Double Ratchet ciphertexts**. Each envelope payload is opaque to servers.

Envelope example:

```json
{
  "type": "MESSAGE",
  "from": "@A4K7...:relay.org+S1",
  "to": "@B9K2...:server.net+QW83XZ12",
  "ratchet_header": {
    "dh_pub": "<base64 ratchet public>",
    "pn": 0,
    "n": 1
  },
  "ciphertext": "<base64>",
  "timestamp": 1690001000
}
```

Servers simply store/forward.

## Offline delivery

* If Bob is offline, server queues envelope in the `mailbox` for his sub-address.
* On Bob connect, `GET /users/{user_id}/pending` returns queued envelopes;
  server may optionally support long-polling/websockets for push.
* Mailbox entries should expire after TTL (configurable).

## Key rotations and sub-address unlinkability

* **OPK rotation**: Clients upload batches of OPKs periodically. Server marks
  consumed OPKs to avoid reuse.
* **Signed bundle rotation**: `signed_prekey` rotates (e.g., every week
  or month). Client signs new bundle with `SIG`.
* **Sub-address unlinkability**:
  - Use per-peer sub-id `HMAC(IK_self, IK_peer)` so that the same user has
    different sub-IDs for different peers, reducing server-side linkability across mailboxes.
  - Optionally store each sub-address in a separate mailbox with independent
    TTL, so `server.net` cannot trivially correlate them. The server still
    sees that it's on their domain, but does not necessarily know these belong to the same user.
* **Address rotation**:
  - Allow client to derive ephemeral addresses (e.g., `+rand`) for one-off
    invite sessions; discard after expiry.
  - For persistent contacts, subids can be deterministic but rotated
    periodically (e.g., change subid salt) to reduce long-term correlation.

## Federation (server→server) (optional)

If you want cross-server delivery without the client directly posting to remote server:

* Alice’s client posts to its own relay at `relay.org`.
* `relay.org` performs DNS discovery for `server.net` and sends via a
  server-to-server secure channel:

```
POST https://server.net/s2s/deliver
Headers: Authentication: mTLS or token + origin
Body: { envelope }
```

`server.net` validates that the `to` mailbox exists, stores the envelope, and
responds with success/failure.

Important S2S privacy/anti-abuse notes:

* Use **mutual TLS** or signed tokens for server authentication.
* Rate-limit and log minimal metadata.
* Optionally relay via proxies or use onion routing if higher anonymity is required.

## Metadata minimization techniques

* **Sealed Sender**: clients can encrypt the "from" field so the relay can’t read the sender (but the server needs to know where to route; solved by use of return routing tokens or envelope headers visible only to recipient server).
* **Onion routing for headers**: wrap routing info separately from payload, possibly with short-lived routing tokens for push.
* **Limit logs**: servers store only the fields required for delivery; TTL short; no persistent association of subids to other subids.
* **Authorization**: require client authentication to upload prekeys; but keep authentication minimal (short-lived tokens) to limit correlation.

## Error cases & anti-abuse

* If prekey bundle is stale/invalid: return HTTP 410 and instruct client to refresh the contact’s address (client should fetch updated bundle).
* If all OPKs consumed: server returns a flag; client may fallback to `SPK` only (non-OPK) or use an invitation flow.
* Rate-limit incoming messages per `from` sub-address and per destination mailbox to mitigate spam.
* Mailbox quota per sub-address to prevent DoS.

## Example end-to-end JSON snippets

**Alice GET prekey-bundle (response):**

```json
{
  "identity_key": "B64(IK_B)",
  "sig_pub": "B64(SIG_B)",
  "signed_prekey": {"id":"spk1", "pub":"B64(SPK_B)", "expiry":1730000000},
  "one_time_prekey": {"id":"opk42","pub":"B64(OPK_B)"},
  "bundle_signature": "B64(Sign(SIG_B, bundle_payload))"
}
```

**Alice POST initial X3DH_INIT (body):**

```json
{
  "envelope": {
    "from": "@A4K7...:relay.org+S1",
    "to": "@B9K2...:server.net+QW83XZ12",
    "type": "X3DH_INIT",
    "x3dh": {
      "alice_ik": "B64(IK_A)",
      "alice_ek": "B64(EK_A)",
      "opk_id_used": "opk42"
    },
    "ciphertext": "B64(encrypted_init_payload)",
    "timestamp": 1690000000
  }
}
```

## Security considerations & recommendations

* **Sign prekey bundles** with `SIG` to prevent server spoofing of bundles.
* **Consume OPKs server-side** atomically to avoid reuse and race conditions.
* **Forward secrecy**: ensure Double Ratchet is implemented per-spec and you handle skipped-message caches.
* **Replay protection**: include nonces/timestamps and reject stale envelopes beyond accepted clock skew.
* **Authorization**: restrict `POST /users/{user_id}/prekeys` to authenticated owner devices (JWT issued on registration).
* **Auditing**: keep server-side logs minimal and ephemeral; provide transparency reports for hosted servers.

## UX & discovery options

* Manual share: QR codes containing `@base:domain+sub`.
* Invite link: `https://server.net/invite/<token>` that contains a one-time
  relay address with embedded prekey bundle (short-lived).
* Private Contact Discovery: server-side PSI or client-side Bloom filter
  exchange (requires careful privacy analysis).


## Next steps

* Draft an **OpenAPI** specification for the endpoints above (useful for Erlang cowboy/plug endpoints).
* Produce **Erlang data structures** and a design for atomic OPK consumption (Mnesia/ETS layout).
* Provide a **sequence diagram** (text or mermaid) of the flows above.
* Create a minimal **reference message format** and example Erlang modules for parsing/validating bundles.


