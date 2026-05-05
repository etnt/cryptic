# Audio Call Feasibility Plan for Cryptic

**Document Version**: 1.0  
**Created**: May 2026  
**Status**: Planning / Feasibility Study

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current Architecture Assessment](#current-architecture-assessment)
3. [Technology Options](#technology-options)
4. [Transport: P2P vs Server-Relay](#transport-p2p-vs-server-relay)
5. [Encryption Model](#encryption-model)
6. [Recommended Approach](#recommended-approach)
7. [Signaling Protocol Design](#signaling-protocol-design)
8. [Server-Side Changes](#server-side-changes)
9. [Client-Side Changes](#client-side-changes)
10. [Security Considerations](#security-considerations)
11. [Implementation Phases](#implementation-phases)
12. [Risks and Open Questions](#risks-and-open-questions)
13. [Decision Summary](#decision-summary)

---

## Executive Summary

This document analyses the feasibility of adding real-time, end-to-end encrypted
audio calls between two Cryptic users. The core questions explored are:

- **Transport**: Should audio travel peer-to-peer (P2P) or be relayed through the
  Cryptic server?
- **Protocol**: Should WebRTC be used, or a lighter bespoke approach?
- **Encryption**: How do we extend Cryptic's existing E2E security guarantees
  (X3DH + Double Ratchet) to cover real-time audio?
- **Client impact**: What does this mean for the terminal-based and Rust TUI
  clients?

### Recommendation in Brief

Use **WebRTC-style signaling** (SDP offer/answer + ICE candidates) transported
over the **existing WebSocket mTLS channel** to negotiate a direct P2P connection.
Audio should travel **peer-to-peer via DTLS-SRTP** whenever NAT allows it, with
**server-side TURN relay** as an automatic fallback. The Double Ratchet session
already established between the two users supplies the key material used to
authenticate the DTLS fingerprints, preventing man-in-the-middle attacks without
requiring a separate key-agreement round-trip.

---

## Current Architecture Assessment

### What Already Exists

| Asset | Relevance to Audio Calls |
|---|---|
| WebSocket mTLS channel (per user) | Perfect signaling channel – always open, authenticated, low-latency |
| `cryptic_event_bus` pub/sub | Delivers call-related events to UI without coupling components |
| `cryptic_ws_handler` (Cowboy) | Easy to add new JSON message types for call signaling |
| X3DH + Double Ratchet sessions | Established shared secret can authenticate DTLS fingerprints |
| mTLS client certificates | Provides authenticated identity for every WebSocket connection |
| `cryptic_nif` (libsodium) | ChaCha20-Poly1305 and X25519 already available for any extra crypto needs |
| ETS `user_connections` table | Can look up peer's WebSocket handler PID for signaling relay |

### Current Limitations Relevant to Audio

1. **No UDP support** – Cryptic today is TCP-only (WebSocket). Real-time audio
   prefers UDP for lower latency, though WebSocket relay is viable for prototypes.
2. **Binary WebSocket frames** marked as "NYI" (Not Yet Implemented) in
   `cryptic_ws_handler`. These would be needed for efficient relay.
3. **Terminal clients** have no built-in audio device abstraction. Audio capture
   and playback require a native library (e.g., PortAudio) callable from Erlang
   or via the Rust TUI.
4. **No STUN/TURN infrastructure** – needed for P2P calls through NAT.

---

## Technology Options

### Option A: Full WebRTC

**What it is**: The W3C/IETF standard for real-time communication in browsers.
Includes ICE (NAT traversal), DTLS (key exchange), SRTP (encrypted audio), SDP
(capability negotiation), and Opus codec.

**Pros**:
- Industry-standard, battle-tested NAT traversal (ICE/STUN/TURN)
- Proven encryption model (DTLS-SRTP, RFC 5764)
- Native support in all modern browsers and many desktop toolkits
- Strong ecosystem: free STUN servers (Google, Cloudflare), TURN libraries
  (coturn), Pion (Go), libwebrtc (C++)

**Cons**:
- **Very heavy**: full WebRTC stacks (libwebrtc) are 10–30 MB compiled,
  and complex to build/maintain
- **Browser-centric APIs** – no native Erlang or straightforward terminal
  client support; would require a Rust NIF (via `webrtc-rs` crate) or
  an external subprocess
- Overkill for a two-party terminal chat tool; browser video features
  unused

**Verdict**: Use WebRTC's **signaling conventions** (SDP, ICE) and its
**DTLS-SRTP media transport**, but do NOT pull in a full WebRTC stack.
This is sometimes called "WebRTC-compatible" or "manual WebRTC".

---

### Option B: DTLS-SRTP Without Full WebRTC Stack

**What it is**: Implement only the relevant RFCs (ICE RFC 8445, DTLS RFC 6347,
SRTP RFC 3711, DTLS-SRTP RFC 5764) using existing Erlang/OTP TLS libraries and
lightweight native code. SDP is replaced by a simpler custom JSON negotiation
format.

**Pros**:
- Much lighter than a full WebRTC stack
- DTLS is already part of Erlang/OTP's `ssl` application (since OTP 23)
- Compatible with any WebRTC peer on the other end if SDP is followed
- Full control over the protocol; fits Cryptic's minimalist philosophy

**Cons**:
- ICE/STUN/TURN implementation is non-trivial
- SRTP support in Erlang requires a NIF or a port driver (no stdlib support)
- Higher implementation effort than using a WebRTC library
- Interop with browser clients would require careful SDP alignment

**Verdict**: Good long-term target, especially for the Erlang server-side TURN
relay. For initial implementation, supplement with a Rust `webrtc-rs` client
module.

---

### Option C: Server-Relayed Audio over WebSocket

**What it is**: Both clients send Opus-encoded audio chunks, encrypted with
Double Ratchet, to the Cryptic server, which relays them to the other party over
their existing WebSocket connection. Pure TCP, no P2P.

**Pros**:
- **Simplest implementation** – no new server ports, no NAT traversal, no STUN/TURN
- Reuses existing Double Ratchet encryption fully
- Works behind any firewall
- No extra dependencies on either client or server

**Cons**:
- **All audio passes through the server**: higher latency (an extra RTT), higher
  server bandwidth load
- Server sees call metadata (who is calling whom, when, duration) even though
  audio content remains E2E encrypted
- Does not scale well if many simultaneous calls
- Not ideal for Cryptic's privacy posture (metadata leakage)

**Verdict**: Viable for a v1 proof-of-concept or as the automatic fallback when
P2P fails (equivalent to TURN relay). Should not be the primary path.

---

### Option D: Bespoke UDP with libsodium

**What it is**: Open a UDP socket directly between the two clients, encrypt
audio frames with ChaCha20-Poly1305 (already in `cryptic_nif`) using a key
derived from the Double Ratchet session, and transmit directly.

**Pros**:
- Lowest latency possible
- Reuses libsodium NIFs already present
- Complete control; no external protocol dependencies

**Cons**:
- NAT traversal is unsolved (requires hole punching or relay, effectively
  re-implementing ICE)
- No codec negotiation, jitter buffering, or RTCP feedback – must implement
  from scratch
- Large engineering effort for marginal gains over DTLS-SRTP

**Verdict**: Not recommended. Re-inventing the wheel without the ecosystem
benefits.

---

## Transport: P2P vs Server-Relay

### Direct P2P (Preferred)

```
Alice ──────────────────────────────────── Bob
         DTLS-SRTP (UDP)
         NAT traversal via ICE
```

- Audio travels directly between Alice and Bob; server is only used for signaling.
- **Lowest latency** (sub-100 ms typically achievable on good networks).
- **Best privacy**: server sees only call setup/teardown signaling, not audio.
- Requires STUN server (to discover public IP/port) and optionally TURN (for
  symmetric NAT fallback).

### Server TURN Relay (Fallback)

```
Alice ──── mTLS WS ──── Cryptic Server ──── mTLS WS ──── Bob
                         (TURN-like relay)
```

- Used automatically when ICE cannot establish a direct path (strict corporate
  NAT, double NAT, etc.).
- Adds ~1 RTT of latency per audio packet; acceptable for voice if server is
  close.
- Audio still E2E encrypted (server cannot decrypt); it relays opaque blobs.
- Can be implemented as a new Cowboy handler (e.g., `/call/relay`) or as new
  WebSocket message types on the existing connection.

### Decision

**P2P first, server relay as automatic fallback.** The ICE mechanism handles
this automatically; the code path is the same on the client.

---

## Encryption Model

### Goal

Maintain Cryptic's guarantee that the server cannot read call audio, and that
a compromised long-term key does not expose past calls.

### Approach: Double Ratchet–Authenticated DTLS

1. **Session key material from Double Ratchet**: When Alice decides to call Bob,
   both sides independently derive a 32-byte "call binding key" `K_call` from
   the current ratchet chain key and a per-call nonce:
   `K_call = HKDF(chain_key, call_nonce, "cryptic_audio_call_v1")`.
   The `call_nonce` is a random 32-byte value generated by the caller and
   included in the encrypted `call_invite` payload (encrypted with the ratchet,
   never transmitted in plaintext). The callee extracts `call_nonce` upon
   decryption and derives the same `K_call` locally — no derived key is ever
   sent over the wire.

2. **DTLS fingerprint binding**: Each client's DTLS certificate is generated
   ephemerally for the call. Its SHA-256 fingerprint is included inside the
   **encrypted** SDP offer/answer (encrypted with the ratchet). On receiving the
   answer, each side verifies the peer's DTLS fingerprint matches what was
   exchanged through the ratchet. This binds the DTLS handshake to the
   authenticated identity.

3. **SRTP via DTLS-SRTP** (RFC 5764): DTLS establishes the master key for SRTP.
   Audio frames are encrypted with SRTP using AEAD_AES_128_GCM (RFC 7714) as
   the mandatory-to-implement profile. Since Cryptic only targets its own
   clients (no browser/WebRTC interop), ChaCha20-Poly1305 via libsodium may be
   used as a Cryptic-specific alternative when both peers support it; however,
   note that there is no published SRTP protection profile for ChaCha20, so any
   such use would be a custom, non-standard extension.

4. **Forward secrecy**: The ephemeral DTLS key pair is discarded after the call.
   The ratchet chain key advances after the call, so past sessions cannot be
   derived.

### Why Not Use Double Ratchet Directly for Audio?

Double Ratchet was designed for low-throughput, store-and-forward messaging.
Audio calls generate 50–100 packets per second; running a KDF per packet would
be prohibitively expensive. DTLS-SRTP's symmetric keys, bootstrapped once from
the ratchet, are the right tool for this bandwidth pattern.

---

## Recommended Approach

### Summary

| Concern | Choice |
|---|---|
| Signaling transport | Existing WebSocket mTLS channel |
| Signaling format | Custom JSON (inspired by SDP/ICE, simpler) |
| Media transport | DTLS-SRTP over UDP (P2P via ICE) |
| Relay fallback | Server-relayed encrypted chunks over WebSocket |
| Encryption root | Double Ratchet session (for DTLS fingerprint binding) |
| Media encryption | SRTP (from DTLS handshake) |
| Audio codec | Opus (best quality/compression for voice) |
| NAT traversal | ICE with public STUN + self-hosted TURN (coturn) |
| Client library | `webrtc-rs` in Rust TUI; Erlang port for console client |

---

## Signaling Protocol Design

All signaling messages travel over the existing WebSocket mTLS channel, using
new JSON message types. They are relayed server-side by looking up the callee's
PID in the `user_connections` ETS table (same mechanism as text messages).

### New Message Types (Client → Server → Client)

#### `call_invite`
Alice wants to call Bob.
```json
{
  "type": "call_invite",
  "call_id": "uuid-1234",
  "from_user": "alice",
  "to_user": "bob",
  "encrypted_payload": "base64..."
}
```
`encrypted_payload` is a Double Ratchet-encrypted blob containing:
```json
{
  "dtls_fingerprint": "sha-256 AA:BB:CC:...",
  "ice_candidates": [
    {"candidate": "candidate:...", "sdpMid": "audio", "sdpMLineIndex": 0}
  ],
  "audio_codecs": ["opus/48000/2"],
  "call_nonce": "base64_random_32_bytes"
}
```

#### `call_answer`
Bob accepts.
```json
{
  "type": "call_answer",
  "call_id": "uuid-1234",
  "from_user": "bob",
  "to_user": "alice",
  "encrypted_payload": "base64..."
}
```
Same payload structure as `call_invite` (Bob's fingerprint + ICE candidates).

#### `call_ice_candidate`
Trickle ICE – send additional candidates as they are discovered.
```json
{
  "type": "call_ice_candidate",
  "call_id": "uuid-1234",
  "from_user": "alice",
  "to_user": "bob",
  "encrypted_candidate": "base64..."
}
```

#### `call_reject`
Bob declines. This is an additional signaling message beyond the core set
(`call_invite`, `call_answer`, `call_ice_candidate`, `call_hangup`); it is
required for a complete call flow but is listed separately as it does not
participate in media negotiation.
```json
{
  "type": "call_reject",
  "call_id": "uuid-1234",
  "from_user": "bob",
  "to_user": "alice",
  "reason": "busy"
}
```

#### `call_hangup`
Either party ends the call.
```json
{
  "type": "call_hangup",
  "call_id": "uuid-1234",
  "from_user": "alice",
  "to_user": "bob"
}
```

### Server Relay Message Types (when P2P fails)

#### `call_relay_frame`
An encrypted Opus audio frame relayed through the server. This message type
is only used in relay mode (Phase 2+) and is not part of the initial
signaling-only phase (Phase 1).
```json
{
  "type": "call_relay_frame",
  "call_id": "uuid-1234",
  "from_user": "alice",
  "to_user": "bob",
  "seq": 42,
  "encrypted_frame": "base64..."
}
```
The server does not decrypt `encrypted_frame`; it routes it by call_id.

### Event Bus Events (Client-Side)

```erlang
%% Incoming call notification
#{type => call_incoming, call_id => <<"uuid">>, from => <<"alice">>}

%% Call was answered by remote peer
#{type => call_answered, call_id => <<"uuid">>}

%% Call ended
#{type => call_ended, call_id => <<"uuid">>, reason => <<"hangup">>}

%% Audio frame received (relay mode)
#{type => call_audio_frame, call_id => <<"uuid">>, frame => <<...>>}
```

---

## Server-Side Changes

### 1. WebSocket Handler (`cryptic_ws_handler.erl`)

Add handlers for the new `call_invite`, `call_answer`, `call_ice_candidate`,
`call_reject`, `call_hangup`, and `call_relay_frame` message types. Routing
logic is identical to text message routing: look up the callee's PID in
`user_connections` ETS and send an Erlang message to that process.

```erlang
%% In websocket_handle/2, add:
handle_call_signaling(Msg = #{<<"type">> := CallType}, State)
    when CallType =:= <<"call_invite">>;
         CallType =:= <<"call_answer">>;
         CallType =:= <<"call_ice_candidate">>;
         CallType =:= <<"call_reject">>;
         CallType =:= <<"call_hangup">> ->
    ToUser = maps:get(<<"to_user">>, Msg),
    relay_to_user(ToUser, Msg),
    {[], State};
```

### 2. TURN Relay (Optional new module: `cryptic_turn_relay.erl`)

A lightweight gen_server that:
- Accepts `call_relay_frame` messages
- Validates that sender is an authenticated participant in the given `call_id`
- Forwards the encrypted frame to the other participant's WebSocket handler PID
- Enforces per-call rate limits and bandwidth caps
- Cleans up state on `call_hangup` or participant disconnect

### 3. Active Call Registry (ETS Table: `cryptic_calls`)

Track active calls to:
- Validate relay frame participants
- Enforce one active call per user
- Trigger cleanup on disconnect

```erlang
%% ETS schema
%% Key: CallId
%% Value: #{caller => <<"alice">>, callee => <<"bob">>,
%%          started_at => erlang:timestamp(),
%%          state => ringing | active | relay}
```

### 4. New Cowboy Route (Optional TURN relay endpoint)

If separate UDP TURN is impractical, expose a WebSocket path for relay:

```erlang
{"/call/relay/[:call_id]", cryptic_turn_relay_handler, []}
```

---

## Client-Side Changes

### Challenge: Audio I/O in a Terminal

The console (`cryptic_console.erl`) and Rust TUI (`cryptic-tui`) are text-based.
Neither has built-in audio capture/playback. This is the biggest practical
challenge.

### Option 1: Rust TUI as the Audio Client (Recommended)

The external Rust TUI (`cryptic-tui`, connected via Erlang distribution protocol)
is the best place to add audio support:

- Use the `webrtc-rs` crate for the full ICE + DTLS-SRTP stack.
- Use `cpal` (Cross-Platform Audio Library) for OS-level audio capture/playback.
- Use `opus` crate for encoding/decoding.
- The TUI communicates call signaling messages to the Erlang node via the
  existing distribution protocol; the Erlang node relays them over WebSocket.

Rust audio pipeline:
```
Microphone → cpal → PCM → opus::Encoder → SRTP → DTLS → UDP → peer
peer → UDP → DTLS → SRTP → opus::Decoder → PCM → cpal → Speaker
```

### Option 2: External Audio Process via Erlang Port

For the terminal Erlang console client, an external C/Rust process handles audio
I/O and communicates with the Erlang node via an Erlang Port (stdin/stdout):

```erlang
Port = open_port({spawn, "cryptic_audio_helper"}, [binary, {packet, 2}])
```

This keeps the Erlang client's dependencies minimal while enabling audio.

### Option 3: Console Client Limitation

The pure Erlang console client (`cryptic_console`) may not support audio in v1.
Users who want calls should use the Rust TUI. This is acceptable and can be
documented as a known limitation.

### New Event Bus Subscriptions

The UI process adds:
```erlang
CallFilter = fun(Event) ->
    case Event of
        #{type := call_incoming}     -> true;
        #{type := call_answered}     -> true;
        #{type := call_ended}        -> true;
        #{type := call_audio_frame}  -> true;  % relay mode only
        _                            -> false
    end
end,
cryptic_event_bus:subscribe(self(), CallFilter).
```

### New CLI Commands (Console)

```
call <user>          # Initiate an audio call
accept               # Accept an incoming call
reject               # Reject an incoming call
hangup               # End the current call
```

---

## Security Considerations

### 1. Identity Binding

The critical security property is that DTLS fingerprints are exchanged **inside
the Double Ratchet-encrypted channel**, not in plaintext. This means an attacker
controlling the server cannot substitute their own DTLS certificate to
man-in-the-middle the audio stream, even in relay mode.

### 2. Server Metadata

Even with E2E encryption, the server learns:
- Who called whom
- When the call started and ended
- Approximate call duration

This is unavoidable with a centrally signalled architecture. Document this clearly.
Future work could explore private contact discovery / sealed sender techniques
for call metadata.

### 3. Relay Mode Privacy

In relay mode, encrypted Opus frames pass through the server. The server cannot
decrypt them (no access to the DTLS keys), but it does see packet sizes and
timing, which could leak information via traffic analysis. Padding audio frames
to a fixed size (e.g., 160 bytes, standard Opus 20 ms frame at 64 kbps) is
recommended.

### 4. Denial of Service

Malicious users could send `call_invite` floods. Mitigations:
- Rate-limit `call_invite` per sender (e.g., max 1 unanswered invite per 10 s).
- Only relay frames for established (answered) calls.
- Enforce call duration limits and bandwidth caps per relay session.

### 5. Certificate Freshness

The ephemeral DTLS certificates generated per-call should have a short TTL (e.g.,
5 minutes). Their fingerprints are authenticated by the ratchet, so the CA is not
involved.

### 6. Key Separation

The `call_nonce` in the encrypted payload ensures each call produces distinct
key material even if the ratchet state is somehow reused. Both sides derive the
call key locally — the caller generates `call_nonce` and includes it in the
encrypted `call_invite`; the callee extracts it and runs the same KDF:
```
K_call = HKDF(chain_key, call_nonce, "cryptic_audio_call_v1")
```
Note: `chain_key` (the current ratchet chain key) is used as the input keying
material, not a per-message key, so it is available to both sides at derivation
time.

---

## Implementation Phases

### Phase 1: Signaling Infrastructure (Server + Basic Client)

**Goal**: Two clients can exchange call signaling over WebSocket.

- [ ] Add call message types to `cryptic_ws_handler.erl`
- [ ] Add `cryptic_calls` ETS table for active call tracking
- [ ] Implement `call_invite` / `call_answer` / `call_hangup` routing
- [ ] Publish call events to `cryptic_event_bus`
- [ ] Add `call`, `accept`, `reject`, `hangup` commands to console (UI only, no audio yet)
- [ ] Write eunit tests for signaling relay

### Phase 2: Server-Relayed Audio (Proof of Concept)

**Goal**: Encrypted audio flows server-relay path; no P2P yet.

- [ ] Implement `cryptic_turn_relay.erl` for frame forwarding
- [ ] Implement `call_relay_frame` handler in `cryptic_ws_handler.erl`
- [ ] Implement Rust TUI audio module (`cpal` + `opus` + relay transport)
- [ ] Derive call key from Double Ratchet session
- [ ] End-to-end test: Alice calls Bob, audio encrypted, relayed

### Phase 3: P2P via ICE/DTLS-SRTP

**Goal**: Audio goes direct P2P; server relay retained as fallback.

- [ ] Deploy STUN server (or use public Google STUN as bootstrap)
- [ ] Deploy TURN relay (coturn recommended)
- [ ] Integrate `webrtc-rs` ICE + DTLS-SRTP in Rust TUI
- [ ] Add trickle ICE candidate exchange to signaling protocol
- [ ] Validate DTLS fingerprints against ratchet-exchanged values
- [ ] Auto-fallback to server relay if ICE fails
- [ ] Performance and latency benchmarking

### Phase 4: Hardening and Polish

- [ ] Audio codec negotiation (Opus mandatory, others optional)
- [ ] Jitter buffer and packet loss concealment
- [ ] Call quality indicators in TUI (packet loss %, latency)
- [ ] Mute / unmute
- [ ] Call history (metadata only: who, when, duration) stored in SQLite
- [ ] Rate limiting and DoS hardening on server
- [ ] Frame padding for traffic analysis resistance
- [ ] Documentation and protocol specification

---

## Risks and Open Questions

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| NAT traversal failures behind strict corporate NAT | Medium | High (call fails) | TURN relay fallback |
| Audio latency too high in relay mode | Medium | Medium | Phase 3 P2P path |
| `webrtc-rs` API instability / maintenance burden | Low | Medium | Pin to stable version; fallback to relay-only |
| Erlang console client cannot do audio | High (certain) | Low | Document; audio only in TUI |
| Server resource exhaustion from relay frames | Low | High | Per-call bandwidth cap + relay session timeouts |
| ICE/STUN/TURN complexity slows Phase 3 | Medium | Medium | Deliver relay-only v1, add P2P in v2 |
| Traffic analysis via relay frame timing | Low | Low | Opus frame padding to fixed size |

### Open Questions

1. **STUN/TURN hosting**: Will Cryptic operators run their own TURN server (coturn),
   or can public STUN suffice for most users? A self-hosted TURN server is strongly
   recommended for privacy but adds operational burden.

2. **Mobile clients**: If a mobile client is ever built, native WebRTC is trivially
   available. The custom signaling format should be kept compatible.

3. **Group calls**: Two-party calls are addressed here. Group calls (N > 2) require
   a selective forwarding unit (SFU) or mesh P2P. Deferred to a future plan.

4. **Video**: The same signaling and transport infrastructure (ICE + DTLS-SRTP)
   supports video with a different codec (H.264, VP8/VP9, AV1). Deferred.

5. **Call recording**: Deliberately excluded from scope to preserve E2E guarantees.

---

## Decision Summary

| Question | Decision | Rationale |
|---|---|---|
| Use WebRTC? | Partially – use its transport layer and signaling conventions, not a full WebRTC stack | Avoids heavy dependency while reusing proven RFCs |
| P2P or server-relay? | P2P preferred; server relay as automatic fallback | Privacy + latency for P2P; reliability from relay |
| How to signal? | Over existing WebSocket mTLS channel, new JSON message types | Zero new infrastructure; authenticated channel already in place |
| How to encrypt audio? | DTLS-SRTP, with DTLS fingerprint authenticated via Double Ratchet | Separates high-throughput SRTP from low-throughput ratchet |
| Audio in Erlang console? | Not in v1; only in Rust TUI | Console has no audio I/O primitives; TUI has `cpal`/`opus` ecosystem |
| NAT traversal? | ICE + self-hosted coturn TURN server | Industry-standard; works behind most NATs |
| Group calls? | Out of scope for this plan | Requires SFU architecture; different problem |

---

**Document Version**: 1.0  
**Last Updated**: May 2026  
**Author**: Generated for Cryptic Project
