# Multi-Device Support — Implementation Proposal

## Problem Statement

A user should be able to run multiple Cryptic clients simultaneously (e.g. a
terminal client and a mobile client) and have them all:

1. **Receive incoming messages** in real-time across all connected devices
2. **Keep sent messages in sync** so that a message sent from one device appears
   in the chat thread on every other device
3. **Maintain cryptographic integrity** — the Double Ratchet protocol must
   remain secure and synchronized across devices

Currently the system is **fundamentally single-device-per-user**. Every key data
structure — connection registry, ratchet sessions, key bundles, message
storage — uses `Username` as the sole identifier with no device dimension.

---

## Current Architecture Constraints

### 1. Connection Registry — One Slot Per User

The server ETS table `?CONNECTION_TABLE` stores `{Username, Pid}` pairs. When a
second device connects with the same username, `ets:insert/2` silently
**overwrites** the previous entry. The first device becomes unreachable, and its
handler process is orphaned without notification.

### 2. Message Routing — Single Recipient

`find_user_connection/1` returns a **single Pid** for a username. Incoming
messages (X3DH or Ratchet) are delivered to that one process. There is no
fan-out to multiple connections.

### 3. Double Ratchet — Shared Mutable State

Ratchet sessions are keyed by `peer_username` alone
(`sessions#{<<"bob">> => Pid}`). If two devices share the same ratchet state,
they will independently advance the chain, producing **duplicate message
numbers** and **breaking forward secrecy**. The Double Ratchet protocol is
inherently a **point-to-point** state machine; it cannot be shared across
devices.

### 4. Identity Keys — One Bundle Per User

The server stores identity keys under `{Username, identity}` and OTPKs under
`{Username, otpk, KeyId}`. A second device uploading its keys **overwrites** the
first device's identity. Peers fetching the key bundle will get whichever device
uploaded last, causing decryption mismatches.

### 5. Authentication — Username Only

The mTLS certificate contains a username (via SAN or CN) but no device
identifier. The server extracts a username from the cert and uses it as the sole
routing key.

---

## Survey of Known Approaches

### A. Signal's Sesame Protocol (Per-Device Sessions)

Signal treats each device as a separate cryptographic endpoint. When Alice sends
a message to Bob who has 3 devices, Alice encrypts the message **three separate
times**, once for each of Bob's devices, using independent Double Ratchet
sessions.

**How it works:**
- Each device has its own identity key pair and set of prekeys
- The server stores key bundles **per (user, device_id)**
- When Alice wants to message Bob, she fetches the key bundle for *each* of
  Bob's devices and performs an independent X3DH + Ratchet session with each
- A single "send message" from Alice produces N ciphertexts (one per device)
- The server delivers each ciphertext to the corresponding device

**Self-messaging for sent-message sync:**
- When Alice sends from Device A, Alice also encrypts the message for her own
  Device B (and any other devices she owns)
- Each of Alice's devices receives the sent message and adds it to the local
  chat thread

**Pros:** Each ratchet session is independent and correct; no shared state.\
**Cons:** Bandwidth and CPU scale with the number of recipient devices; adding a
new device requires establishing fresh sessions with all peers.

### B. Matrix/MegOLM (Shared Group Key)

Matrix uses MegOLM for group encryption: a single session key encrypts messages,
and each device receives the session key encrypted to its own Olm (Double
Ratchet) session. This is optimized for rooms with many participants but also
works for multi-device.

**How it works:**
- The sender creates a MegOLM *outbound session* with a single ratchet
- The session key is distributed to each recipient device via pairwise Olm
  sessions
- Messages are encrypted once with the MegOLM ratchet
- Any device holding the session key can decrypt

**Pros:** Message encrypted only once regardless of device count (efficient for groups).\
**Cons:** Significantly more complex; requires a separate key-distribution
protocol; ratchet provides forward secrecy but not per-message PFS like Double
Ratchet.

### C. Fan-Out at Server (Cleartext Re-Encryption) — NOT SUITABLE

Some systems decrypt at the server and re-encrypt per device. **This breaks
end-to-end encryption** and is not considered here.

---

## Proposed Approach: Per-Device Sessions (Signal-Style)

Given that Cryptic already implements X3DH + Double Ratchet and prioritizes
end-to-end encryption, the Signal/Sesame per-device model is the natural fit. It
keeps each ratchet session independent and correct, requiring no changes to the
core cryptographic primitives.

### Core Concept: Device ID

Introduce a `DeviceId` (e.g. a random 32-bit integer or short string generated
at first launch) that uniquely identifies a device within a user account.

The composite key for all operations becomes `{Username, DeviceId}` instead of
just `Username`.

---

## Detailed Design

### Phase 1: Device Identity & Registration

#### 1.1 Device ID Generation

Each client generates a `DeviceId` on first launch, stored locally alongside
identity keys in `~/.cryptic/<username>/<server>_<port>/device_id`.

```erlang
%% Generate once at first launch
DeviceId = integer_to_binary(
    binary:decode_unsigned(crypto:strong_rand_bytes(4))
),
file:write_file(DeviceIdPath, DeviceId).
```

#### 1.2 Certificate Extension (Optional, Recommended)

Embed the DeviceId in the client certificate as a custom SAN or X.509 extension.
This lets the server extract it during mTLS handshake:

```
X509v3 Subject Alternative Name:
    otherName:1.3.6.1.4.1.XXXX.1;UTF8:device-a3f7b2c1
```

Alternatively, the client can send the DeviceId in the initial WebSocket
handshake message if cert changes are too disruptive.

#### 1.3 Device Registration on Server

New WebSocket command to register a device:

```json
{
  "type": "register_device",
  "device_id": "a3f7b2c1",
  "device_name": "Terminal (laptop)"
}
```

Server stores in a new ETS table or extends user registration:

```erlang
%% ?DEVICE_TABLE: {Username, DeviceId} -> DeviceInfo
ets:insert(?DEVICE_TABLE, {{Username, DeviceId}, #{
    device_name => DeviceName,
    registered_at => erlang:system_time(second),
    last_seen => erlang:system_time(second)
}}).
```

New command to list a user's devices:

```json
{
  "type": "list_devices",
  "username": "bob"
}
```

Response:

```json
{
  "type": "devices",
  "username": "bob",
  "devices": [
    {"device_id": "a3f7b2c1", "device_name": "Terminal (laptop)"},
    {"device_id": "7e2d9f04", "device_name": "Mobile"}
  ]
}
```

### Phase 2: Per-Device Key Bundles

#### 2.1 Upload Keys Per Device

Change the key upload to include `device_id`:

```json
{
  "type": "upload_identity_keys",
  "device_id": "a3f7b2c1",
  "identity_sign_public": "base64...",
  "identity_dh_public": "base64...",
  "signed_prekey_public": "base64...",
  "signed_prekey_signature": "base64..."
}
```

Server storage key changes from `{Username, identity}` to
`{Username, DeviceId, identity}`:

```erlang
store_identity_keys(Username, DeviceId, IdentityKeys) ->
    ets:insert(?PREKEY_TABLE, {{Username, DeviceId, identity}, IdentityData}).
```

OTPKs similarly become `{Username, DeviceId, otpk, KeyId}`.

#### 2.2 Fetch Key Bundles For All Devices

When Alice wants to message Bob, she requests key bundles for **all of Bob's
devices**:

```json
{"type": "get_key_bundles", "username": "bob"}
```

Response:

```json
{
  "type": "key_bundles",
  "username": "bob",
  "bundles": [
    {
      "device_id": "a3f7b2c1",
      "identity_sign_public": "...",
      "identity_dh_public": "...",
      "signed_prekey": {...},
      "one_time_prekey": {...}
    },
    {
      "device_id": "7e2d9f04",
      "identity_sign_public": "...",
      ...
    }
  ]
}
```

The existing `get_key_bundle` (singular) can remain for backward compatibility
and return the bundle for the primary or any single device.

### Phase 3: Per-Device Ratchet Sessions

#### 3.1 Session Keying

Change the engine session map from `#{PeerUsername => SessionPid}` to
`#{  {PeerUsername, PeerDeviceId} => SessionPid  }`:

```erlang
%% Before
sessions :: #{binary() => pid()}
%% After
sessions :: #{{binary(), binary()} => pid()}
```

Session file storage changes from:
```
sessions/bob.session
```
to:
```
sessions/bob_a3f7b2c1.session
sessions/bob_7e2d9f04.session
```

#### 3.2 Sending a Message

When the user sends a plaintext message to Bob, the engine:

1. Looks up all of Bob's registered device IDs (cached or fetched from server)
2. For each `{bob, DeviceId}`:
   - Retrieves or establishes a ratchet session
   - Encrypts the plaintext, producing a per-device ciphertext
3. Also encrypts for the sender's **own other devices** (for sent-message sync)
4. Sends all ciphertexts to the server in a single batch

```json
{
  "type": "send_message",
  "to_user": "bob",
  "messages": [
    {
      "to_device": "a3f7b2c1",
      "message_type": "ratchet",
      "ciphertext": "base64...",
      "dh_public": "base64...",
      "previous_chain_length": 5,
      "message_number": 3
    },
    {
      "to_device": "7e2d9f04",
      "message_type": "x3dh",
      "ciphertext": "base64...",
      "identity_key": "base64...",
      "ephemeral_key": "base64..."
    }
  ],
  "self_messages": [
    {
      "to_device": "other-self-device-id",
      "message_type": "ratchet",
      "ciphertext": "base64..."
    }
  ]
}
```

### Phase 4: Multi-Device Connection Registry & Routing

#### 4.1 Connection Registry

Change from `{Username, Pid}` to a **bag** or list-based structure:

```erlang
%% Option A: ETS bag type
ets:new(?CONNECTION_TABLE, [named_table, bag, public]).
%% Stores: {Username, DeviceId, Pid}

register_user_connection(Username, DeviceId, Pid) ->
    ets:insert(?CONNECTION_TABLE, {Username, DeviceId, Pid}).
```

`find_user_connections/1` returns a list:

```erlang
find_user_connections(Username) ->
    Connections = ets:match_object(?CONNECTION_TABLE, {Username, '_', '_'}),
    %% Filter dead processes
    Alive = [{DeviceId, Pid}
             || {_, DeviceId, Pid} <- Connections,
                is_process_alive(Pid)],
    %% Clean up stale entries
    ...
    Alive.
```

#### 4.2 Message Routing

When the server receives a message with per-device ciphertexts:

```erlang
route_message(ToUser, DeviceMessages) ->
    Connections = find_user_connections(ToUser),
    lists:foreach(fun(#{to_device := DeviceId, ciphertext := CT} = Msg) ->
        case lists:keyfind(DeviceId, 1, Connections) of
            {DeviceId, Pid} ->
                %% Device online — deliver immediately
                Pid ! {message, Msg};
            false ->
                %% Device offline — store for later
                store_pending_message(ToUser, DeviceId, Msg)
        end
    end, DeviceMessages).
```

#### 4.3 Pending Message Storage

Change from `{MessageId, ToUser, MessageBlob}` to
`{MessageId, ToUser, ToDeviceId, MessageBlob}`:

```erlang
store_pending_message(ToUser, DeviceId, Msg) ->
    MsgId = erlang:unique_integer([positive]),
    ets:insert(?MESSAGE_TABLE, {MsgId, ToUser, DeviceId, Msg}).
```

On reconnection, a device receives only its own pending messages:

```erlang
get_pending_messages(Username, DeviceId) ->
    Matching = [{Id, Blob}
                || {Id, ToUser, ToDev, Blob} <- ets:tab2list(?MESSAGE_TABLE),
                   ToUser == Username, ToDev == DeviceId],
    Sorted = lists:keysort(1, Matching),
    [begin ets:delete(?MESSAGE_TABLE, Id), Blob end
     || {Id, Blob} <- Sorted].
```

### Phase 5: Sent-Message Sync (Self-Messaging)

When Alice sends a message from Device A, the engine also encrypts the plaintext
for each of Alice's **other** devices using their respective ratchet sessions.
These are delivered as regular encrypted messages tagged with a
`"self_sync": true` flag so the receiving device knows to insert them as
*outgoing* messages in the chat thread, not incoming.

```json
{
  "type": "message",
  "message_type": "ratchet",
  "from_user": "alice",
  "from_device": "a3f7b2c1",
  "to_user": "alice",
  "to_device": "7e2d9f04",
  "self_sync": true,
  "original_to": "bob",
  "ciphertext": "base64..."
}
```

The receiving device decrypts and sees:
- `self_sync: true` → this is a message I sent from another device
- `original_to: "bob"` → display in the Bob conversation as a sent message

---

## Migration & Backward Compatibility

### Phased Rollout

1. **Phase 0 (no code changes):** Single-device behavior is the default.
   Clients that don't send a `device_id` are assigned a default device ID
   (`"default"`) by the server, preserving current behavior exactly.

2. **Phase 1–2:** Server accepts per-device key bundles alongside legacy
   single-user bundles. `get_key_bundle` (singular) still works and returns the
   default device's bundle.

3. **Phase 3–5:** New clients use `get_key_bundles` (plural) and fan-out
   encryption. Old clients continue to work as single-device users.

### Key Storage Migration

Existing key files (`keys.encrypted`, `sessions/*.session`) remain valid as-is
for the `"default"` device. New devices generate their own keys in a device-
specific subdirectory:

```
~/.cryptic/alice/localhost_8443/
├── device_id                          # "default" for migrated client
├── keys.encrypted                     # default device keys (unchanged)
├── sessions/
│   ├── bob.session                    # legacy format (treated as bob_default)
│   └── bob_a3f7b2c1.session          # new format
└── devices/
    └── 7e2d9f04/
        ├── keys.encrypted
        └── sessions/
            ├── bob_a3f7b2c1.session
            └── alice_a3f7b2c1.session  # self-sync session
```

---

## Summary of Server-Side Changes

| Module | Change |
|--------|--------|
| `cryptic_ws_handler` | Add `device_id` to connection registry (bag ETS); per-device key bundle storage & retrieval; per-device message routing and pending storage; new `register_device` / `list_devices` commands |
| `cryptic_lib` | Per-device key storage paths; `get_pending_messages/2` takes DeviceId |
| `cryptic_engine` | Session map keyed by `{PeerUsername, PeerDeviceId}`; fan-out encryption to all peer devices + self devices on send |
| `cryptic_console_callbacks` | Load/save sessions with device-qualified filenames |
| `cryptic_ws_client` | Send `device_id` at connection time; include `device_id` in outbound messages |
| Certificate / CA | (Optional) embed DeviceId in cert SAN extension |

## Summary of Client-Side Changes

| Component | Change |
|-----------|--------|
| First launch | Generate and persist a `DeviceId` |
| Key upload | Include `device_id` in `upload_identity_keys` and `upload_prekey_bundle` |
| Sending | Fetch all peer device bundles; encrypt once per device; send batch |
| Receiving | Tag messages with `from_device`; accept `self_sync` messages and display as sent |
| Session storage | Store sessions as `<peer>_<device_id>.session` |

---

## Complexity & Risk Assessment

| Area | Complexity | Risk | Notes |
|------|-----------|------|-------|
| Device registration | Low | Low | New ETS table + two new WebSocket commands |
| Per-device key bundles | Medium | Medium | Storage schema change; must not break existing single-device clients |
| Per-device ratchet sessions | Medium | High | Core crypto path; session key change affects all message flow |
| Fan-out encryption | Medium | Medium | CPU/bandwidth scales linearly with device count |
| Sent-message sync | Medium | Medium | Self-messaging requires device discovery + extra ratchet sessions |
| Connection registry (bag) | Low | Low | Straightforward ETS change |
| Message routing | Medium | Medium | Must handle mixed online/offline devices per user |
| Migration | Low | Medium | Default device fallback keeps old clients working |

---

## Open Questions

1. **Device limit**: Should there be a maximum number of devices per user?
   Signal caps at 5 linked devices.

2. **Device removal**: When a device is unlinked, what happens to its ratchet
   sessions? Peers need to stop encrypting for it. A `device_removed`
   notification may be needed.

3. **New device catch-up**: When a new device is added, it has no message
   history. Should there be a mechanism to transfer encrypted history from an
   existing device, or does the new device only see messages from the point it
   was linked?

4. **Device verification**: Should users be able to verify each other's device
   fingerprints (like Signal's safety numbers) to guard against device injection
   attacks?

5. **OTPK replenishment per device**: Each device needs its own pool of one-time
   prekeys. The server must track low OTPK counts per device and request
   replenishment independently.

6. **Ordering guarantees**: With self-sync messages, how do we ensure consistent
   message ordering across devices? A server-assigned monotonic timestamp on
   each message could help.
