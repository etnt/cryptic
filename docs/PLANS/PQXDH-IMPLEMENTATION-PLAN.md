# PQXDH Implementation Plan for Cryptic

> **Status**: Planning  
> **Created**: December 2024  
> **Target OTP**: 28.1+  
> **Protocol Reference**: [Signal PQXDH Specification](https://signal.org/docs/specifications/pqxdh/)

## Executive Summary

This document outlines the migration path from X3DH to PQXDH (Post-Quantum
Extended Diffie-Hellman) in the Cryptic messaging system. PQXDH provides
**hybrid post-quantum security** by combining classical X25519 ECDH with
ML-KEM (Kyber) key encapsulation, ensuring security against both classical
and quantum adversaries.

---

## Table of Contents

1. [Background](#1-background)
2. [Current State Analysis](#2-current-state-analysis)
3. [PQXDH Protocol Overview](#3-pqxdh-protocol-overview)
4. [Implementation Phases](#4-implementation-phases)
5. [Key Format Changes](#5-key-format-changes)
6. [Wire Protocol Changes](#6-wire-protocol-changes)
7. [Migration Strategy](#7-migration-strategy)
8. [Testing Plan](#8-testing-plan)
9. [Security Considerations](#9-security-considerations)
10. [Timeline Estimate](#10-timeline-estimate)

---

## 1. Background

### Why PQXDH?

Quantum computers capable of breaking elliptic curve cryptography
(Shor's algorithm) are anticipated within 10-20 years. PQXDH provides:

- **Harvest-now-decrypt-later protection**: Messages encrypted today remain
  secure even if quantum computers emerge
- **Hybrid security**: If ML-KEM is broken, X25519 still provides classical security
- **Forward compatibility**: Prepares Cryptic for the post-quantum era

### OTP 28 Enablement

As of OTP 28.1, Erlang's `crypto` module supports ML-KEM:

```erlang
%% Available KEM algorithms
crypto:supports(kems).  %% => [mlkem512, mlkem768, mlkem1024]

%% Key generation
{PubKey, PrivKey} = crypto:generate_key(mlkem768, []).

%% Encapsulation (sender)
{SharedSecret, Ciphertext} = crypto:encapsulate_key(mlkem768, PubKey).

%% Decapsulation (receiver)
SharedSecret = crypto:decapsulate_key(mlkem768, PrivKey, Ciphertext).
```

---

## 2. Current State Analysis

### Current X3DH Key Bundle

```erlang
#{
    %% Identity Keys (Ed25519 for signing, X25519 for DH)
    identity_sign_private => <<32 bytes>>,
    identity_sign_public => <<32 bytes>>,
    identity_dh_private => <<32 bytes>>,
    identity_dh_public => <<32 bytes>>,
    
    %% Signed Prekey (X25519, rotated periodically)
    signed_prekey_private => <<32 bytes>>,
    signed_prekey_public => <<32 bytes>>,
    signed_prekey_signature => <<64 bytes>>,
    
    %% One-Time Prekeys (X25519, single use)
    one_time_prekeys => [#{id => <<16 bytes>>, 
                           private => <<32 bytes>>, 
                           public => <<32 bytes>>}, ...]
}
```

### Current X3DH Shared Secret Derivation

```
DH1 = ECDH(IK_A, SPK_B)     # Initiator identity ↔ Responder signed prekey
DH2 = ECDH(EK_A, IK_B)      # Initiator ephemeral ↔ Responder identity
DH3 = ECDH(EK_A, SPK_B)     # Initiator ephemeral ↔ Responder signed prekey
DH4 = ECDH(EK_A, OPK_B)     # Initiator ephemeral ↔ Responder one-time prekey (optional)

SK = HKDF(DH1 || DH2 || DH3 || DH4)
```

### Files to Modify

| File                                | Purpose                       | Changes |
|-------------------------------------|-------------------------------|---------|
| `src/cryptic_lib.erl`               | Key generation, X3DH protocol | Add PQ keys, modify protocol |
| `src/cryptic_engine.erl`            | Session management            | Handle PQ key bundles |
| `src/cryptic_ws_handler.erl`        | Server-side message handling  | New message types |
| `src/cryptic_ws_client.erl`         | Client WebSocket              | New message handling |
| `src/cryptic_console_callbacks.erl` | Storage callbacks             | Larger key storage |
| `include/cryptic.hrl`               | Record definitions            | New key fields |

---

## 3. PQXDH Protocol Overview

### PQXDH Key Bundle (New)

```erlang
#{
    %% === Classical Keys (unchanged) ===
    identity_sign_private => <<32 bytes>>,
    identity_sign_public => <<32 bytes>>,
    identity_dh_private => <<32 bytes>>,
    identity_dh_public => <<32 bytes>>,
    signed_prekey_private => <<32 bytes>>,
    signed_prekey_public => <<32 bytes>>,
    signed_prekey_signature => <<64 bytes>>,
    one_time_prekeys => [...],
    
    %% === Post-Quantum Keys (NEW) ===
    pqkem_prekey_private => <<2400 bytes>>,      % ML-KEM-768 private
    pqkem_prekey_public => <<1184 bytes>>,       % ML-KEM-768 public
    pqkem_prekey_signature => <<64 bytes>>,      % Ed25519 signature
    pqkem_prekey_id => <<16 bytes>>,             % Unique identifier
    
    %% Optional: PQ One-Time Prekeys
    pq_one_time_prekeys => [#{
        id => <<16 bytes>>,
        private => <<2400 bytes>>,
        public => <<1184 bytes>>
    }, ...]
}
```

### PQXDH Shared Secret Derivation

```
DH1 = ECDH(IK_A, SPK_B)      # Same as X3DH
DH2 = ECDH(EK_A, IK_B)      # Same as X3DH
DH3 = ECDH(EK_A, SPK_B)     # Same as X3DH
DH4 = ECDH(EK_A, OPK_B)     # Same as X3DH (optional)

# NEW: Post-Quantum KEM
(SS_pq, CT_pq) = Encapsulate(PQPK_B)

# Combined derivation
SK = HKDF(DH1 || DH2 || DH3 || DH4 || SS_pq)
```

### Key Size Comparison

| Key Type           | X3DH Size  | PQXDH Size   | Increase |
|--------------------|------------|--------------|----------|
| Public Key Bundle  | ~200 bytes | ~1,400 bytes | 7x       |
| Private Key Bundle | ~300 bytes | ~2,800 bytes | 9x       |
| Initial Message    | ~150 bytes | ~1,300 bytes | 8.6x     |

---

## 4. Implementation Phases

### Phase 1: Infrastructure (Week 1-2)

#### 1.1 Add OTP Crypto Abstraction Layer

Create `src/cryptic_pq.erl` for post-quantum operations:

```erlang
-module(cryptic_pq).
-export([
    generate_kem_keypair/0,
    generate_kem_keypair/1,
    encapsulate/1,
    decapsulate/2,
    kem_public_key_size/1,
    kem_private_key_size/1,
    kem_ciphertext_size/1
]).

-type kem_algorithm() :: mlkem512 | mlkem768 | mlkem1024.
-type kem_public_key() :: binary().
-type kem_private_key() :: binary().
-type kem_ciphertext() :: binary().
-type shared_secret() :: binary().

%% @doc Generate ML-KEM-768 keypair (default, recommended)
-spec generate_kem_keypair() -> {kem_public_key(), kem_private_key()}.
generate_kem_keypair() ->
    generate_kem_keypair(mlkem768).

-spec generate_kem_keypair(kem_algorithm()) -> {kem_public_key(), kem_private_key()}.
generate_kem_keypair(Algorithm) ->
    crypto:generate_key(Algorithm, []).

%% @doc Encapsulate shared secret for recipient's public key
-spec encapsulate(kem_public_key()) -> {shared_secret(), kem_ciphertext()}.
encapsulate(PublicKey) ->
    encapsulate(mlkem768, PublicKey).

encapsulate(Algorithm, PublicKey) ->
    crypto:encapsulate_key(Algorithm, PublicKey).

%% @doc Decapsulate shared secret using private key
-spec decapsulate(kem_ciphertext(), kem_private_key()) -> shared_secret().
decapsulate(Ciphertext, PrivateKey) ->
    decapsulate(mlkem768, Ciphertext, PrivateKey).

decapsulate(Algorithm, Ciphertext, PrivateKey) ->
    crypto:decapsulate_key(Algorithm, PrivateKey, Ciphertext).

%% Size constants for ML-KEM-768
kem_public_key_size(mlkem768) -> 1184;
kem_public_key_size(mlkem512) -> 800;
kem_public_key_size(mlkem1024) -> 1568.

kem_private_key_size(mlkem768) -> 2400;
kem_private_key_size(mlkem512) -> 1632;
kem_private_key_size(mlkem1024) -> 3168.

kem_ciphertext_size(mlkem768) -> 1088;
kem_ciphertext_size(mlkem512) -> 768;
kem_ciphertext_size(mlkem1024) -> 1568.
```

#### 1.2 Update Key Bundle Type Specifications

Add to `include/cryptic.hrl`:

```erlang
-type protocol_version() :: x3dh | pqxdh.

-record(pqkem_prekey, {
    id :: binary(),
    public :: binary(),
    private :: binary(),
    signature :: binary(),
    created_at :: integer()
}).

-record(key_bundle_v2, {
    version = pqxdh :: protocol_version(),
    %% Classical keys
    identity_sign_key :: {binary(), binary()},
    identity_dh_key :: {binary(), binary()},
    signed_prekey :: #signed_prekey{},
    one_time_prekeys :: [#one_time_prekey{}],
    %% Post-quantum keys
    pqkem_prekey :: #pqkem_prekey{},
    pq_one_time_prekeys = [] :: [#pqkem_prekey{}]
}).
```

### Phase 2: Key Generation (Week 2-3)

#### 2.1 Extend `generate_client_keys/0`

```erlang
%% In cryptic_lib.erl

-spec generate_client_keys() -> key_bundle().
generate_client_keys() ->
    generate_client_keys(pqxdh).  % Default to PQXDH

-spec generate_client_keys(protocol_version()) -> key_bundle().
generate_client_keys(x3dh) ->
    generate_client_keys_x3dh();  % Existing implementation
generate_client_keys(pqxdh) ->
    generate_client_keys_pqxdh().

generate_client_keys_pqxdh() ->
    %% Generate classical keys (same as before)
    ClassicalKeys = generate_client_keys_x3dh(),
    
    %% Generate PQ KEM prekey
    {PQPrekeyPub, PQPrekeyPriv} = cryptic_pq:generate_kem_keypair(),
    PQPrekeyId = crypto:strong_rand_bytes(16),
    
    %% Sign PQ prekey with identity signing key
    IdentitySignPriv = maps:get(identity_sign_private, ClassicalKeys),
    PQPrekeySignature = crypto:sign(
        eddsa, none, PQPrekeyPub, [IdentitySignPriv, ed25519]
    ),
    
    %% Merge with classical keys
    ClassicalKeys#{
        protocol_version => pqxdh,
        pqkem_prekey_id => PQPrekeyId,
        pqkem_prekey_private => PQPrekeyPriv,
        pqkem_prekey_public => PQPrekeyPub,
        pqkem_prekey_signature => PQPrekeySignature,
        pq_one_time_prekeys => generate_pq_one_time_prekeys(5)
    }.

generate_pq_one_time_prekeys(Count) ->
    [begin
        {Pub, Priv} = cryptic_pq:generate_kem_keypair(),
        #{
            id => crypto:strong_rand_bytes(16),
            public => Pub,
            private => Priv
        }
    end || _ <- lists:seq(1, Count)].
```

### Phase 3: PQXDH Protocol (Week 3-4)

#### 3.1 PQXDH Initiator (Sender)

```erlang
%% In cryptic_lib.erl

-spec perform_pqxdh_initiator(key_bundle(), recipient_bundle()) ->
    {ok, shared_secret(), initial_message()} | {error, term()}.
perform_pqxdh_initiator(SenderKeys, RecipientBundle) ->
    %% Validate recipient's PQ prekey signature
    case verify_pqkem_prekey(RecipientBundle) of
        false -> {error, invalid_pqkem_signature};
        true ->
            %% Classical X3DH DH operations
            {DH1, DH2, DH3, DH4} = compute_x3dh_dh_values(
                SenderKeys, RecipientBundle
            ),
            
            %% Generate ephemeral X25519 key
            {EphemeralPub, EphemeralPriv} = crypto:generate_key(ecdh, x25519),
            
            %% NEW: ML-KEM encapsulation
            PQPrekeyPub = maps:get(pqkem_prekey_public, RecipientBundle),
            {SSPq, CTPq} = cryptic_pq:encapsulate(PQPrekeyPub),
            
            %% Combine all secrets
            IKM = <<DH1/binary, DH2/binary, DH3/binary, DH4/binary, SSPq/binary>>,
            
            %% Derive shared secret via HKDF
            Info = <<"PQXDH_SharedSecret">>,
            SharedSecret = hkdf_sha256(IKM, <<>>, Info, 32),
            
            %% Build initial message
            InitialMessage = #{
                protocol_version => pqxdh,
                identity_key => maps:get(identity_dh_public, SenderKeys),
                ephemeral_key => EphemeralPub,
                pqkem_ciphertext => CTPq,
                used_one_time_prekey_id => get_opk_id(RecipientBundle),
                used_pqkem_prekey_id => maps:get(pqkem_prekey_id, RecipientBundle)
            },
            
            {ok, SharedSecret, InitialMessage}
    end.

verify_pqkem_prekey(RecipientBundle) ->
    PQPrekeyPub = maps:get(pqkem_prekey_public, RecipientBundle),
    PQPrekeySignature = maps:get(pqkem_prekey_signature, RecipientBundle),
    IdentitySignPub = maps:get(identity_sign_public, RecipientBundle),
    
    crypto:verify(eddsa, none, PQPrekeyPub, PQPrekeySignature, 
                  [IdentitySignPub, ed25519]).
```

#### 3.2 PQXDH Responder (Receiver)

```erlang
-spec perform_pqxdh_responder(key_bundle(), initial_message()) ->
    {ok, shared_secret()} | {error, term()}.
perform_pqxdh_responder(ReceiverKeys, InitialMessage) ->
    %% Classical X3DH DH operations
    {DH1, DH2, DH3, DH4} = compute_x3dh_dh_responder(
        ReceiverKeys, InitialMessage
    ),
    
    %% NEW: ML-KEM decapsulation
    CTPq = maps:get(pqkem_ciphertext, InitialMessage),
    PQPrekeyId = maps:get(used_pqkem_prekey_id, InitialMessage),
    
    case find_pqkem_prekey(PQPrekeyId, ReceiverKeys) of
        {ok, PQPrivKey} ->
            SSPq = cryptic_pq:decapsulate(CTPq, PQPrivKey),
            
            %% Combine all secrets (same order as initiator)
            IKM = <<DH1/binary, DH2/binary, DH3/binary, DH4/binary, SSPq/binary>>,
            
            %% Derive shared secret via HKDF
            Info = <<"PQXDH_SharedSecret">>,
            SharedSecret = hkdf_sha256(IKM, <<>>, Info, 32),
            
            {ok, SharedSecret};
        {error, Reason} ->
            {error, Reason}
    end.
```

### Phase 4: Wire Protocol (Week 4-5)

#### 4.1 New Message Types

```erlang
%% Upload PQXDH key bundle
#{
    <<"type">> => <<"upload_pqxdh_keys">>,
    <<"username">> => <<"alice">>,
    %% Classical keys (base64)
    <<"identity_sign_public">> => <<"...">>,
    <<"identity_dh_public">> => <<"...">>,
    <<"signed_prekey_public">> => <<"...">>,
    <<"signed_prekey_signature">> => <<"...">>,
    <<"signed_prekey_id">> => 1,
    %% PQ keys (base64)
    <<"pqkem_prekey_public">> => <<"...">>,        % ~1580 chars base64
    <<"pqkem_prekey_signature">> => <<"...">>,
    <<"pqkem_prekey_id">> => <<"...">>
}

%% PQXDH initial message
#{
    <<"type">> => <<"pqxdh">>,
    <<"message_id">> => <<"uuid">>,
    <<"from_user">> => <<"alice">>,
    <<"to_user">> => <<"bob">>,
    <<"identity_key">> => <<"...">>,
    <<"ephemeral_key">> => <<"...">>,
    <<"pqkem_ciphertext">> => <<"...">>,           % ~1450 chars base64
    <<"used_one_time_prekey_id">> => 5,
    <<"used_pqkem_prekey_id">> => <<"...">>,
    <<"ciphertext">> => <<"...">>
}
```

#### 4.2 Key Bundle Response

```erlang
%% Get key bundle response (PQXDH)
#{
    <<"type">> => <<"key_bundle">>,
    <<"protocol_version">> => <<"pqxdh">>,
    <<"username">> => <<"bob">>,
    %% Classical keys
    <<"identity_sign_key">> => <<"...">>,
    <<"identity_dh_key">> => <<"...">>,
    <<"signed_prekey">> => #{
        <<"key_id">> => 1,
        <<"public_key">> => <<"...">>,
        <<"signature">> => <<"...">>
    },
    <<"one_time_prekey">> => #{
        <<"key_id">> => 5,
        <<"public_key">> => <<"...">>
    },
    %% PQ keys
    <<"pqkem_prekey">> => #{
        <<"key_id">> => <<"...">>,
        <<"public_key">> => <<"...">>,            % 1184 bytes → ~1580 base64
        <<"signature">> => <<"...">>
    }
}
```

### Phase 5: Storage Updates (Week 5-6)

#### 5.1 Key Storage Format

Update `cryptic_console_callbacks.erl` for larger keys:

```erlang
%% Key file format v2 with PQ keys
save_identity_keys_v2(Username, Keys, Context) ->
    %% Serialize with protocol version marker
    KeyData = term_to_binary(Keys#{format_version => 2}),
    
    %% Encrypt with passphrase (existing mechanism)
    Passphrase = maps:get(passphrase, Context),
    EncryptedData = cryptic_lib:encrypt_with_passphrase(KeyData, Passphrase),
    
    %% Save to file (will be larger: ~5KB vs ~500 bytes)
    KeyFile = get_key_file_path(Username, Context),
    file:write_file(KeyFile, EncryptedData).
```

#### 5.2 Database Schema Update

```sql
-- Add PQ prekey columns to key_bundles table
ALTER TABLE key_bundles ADD COLUMN pqkem_prekey_public BLOB;
ALTER TABLE key_bundles ADD COLUMN pqkem_prekey_signature BLOB;
ALTER TABLE key_bundles ADD COLUMN pqkem_prekey_id BLOB;
ALTER TABLE key_bundles ADD COLUMN protocol_version TEXT DEFAULT 'x3dh';

-- New table for PQ one-time prekeys
CREATE TABLE pq_one_time_prekeys (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    key_id BLOB NOT NULL,
    public_key BLOB NOT NULL,
    private_key_encrypted BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    used_at INTEGER,
    UNIQUE(username, key_id)
);
```

---

## 5. Key Format Changes

### Public Key Bundle (Server-Stored)

| Field | X3DH | PQXDH | Notes |
|-------|------|-------|-------|
| identity_sign_public | 32 B | 32 B | Unchanged |
| identity_dh_public | 32 B | 32 B | Unchanged |
| signed_prekey_public | 32 B | 32 B | Unchanged |
| signed_prekey_signature | 64 B | 64 B | Unchanged |
| one_time_prekey (×10) | 320 B | 320 B | Unchanged |
| **pqkem_prekey_public** | - | **1184 B** | NEW |
| **pqkem_prekey_signature** | - | **64 B** | NEW |
| **Total** | ~480 B | ~1,730 B | **3.6× larger** |

### Initial Message

| Field | X3DH | PQXDH | Notes |
|-------|------|-------|-------|
| identity_key | 32 B | 32 B | Unchanged |
| ephemeral_key | 32 B | 32 B | Unchanged |
| used_opk_id | 16 B | 16 B | Unchanged |
| ciphertext | Variable | Variable | Unchanged |
| **pqkem_ciphertext** | - | **1088 B** | NEW |
| **Total (min)** | ~80 B | ~1,170 B | **14× larger** |

---

## 6. Wire Protocol Changes

### Backward Compatibility

```erlang
%% Server handles both protocols
handle_get_key_bundle(Username, RequestedVersion) ->
    Bundle = fetch_user_bundle(Username),
    case {RequestedVersion, maps:get(protocol_version, Bundle, x3dh)} of
        {x3dh, _} ->
            %% Client wants X3DH, strip PQ keys
            strip_pq_keys(Bundle);
        {pqxdh, pqxdh} ->
            %% Both support PQXDH
            Bundle;
        {pqxdh, x3dh} ->
            %% Client wants PQXDH but user only has X3DH
            {error, pqxdh_not_available};
        {any, Version} ->
            %% Client accepts either
            Bundle
    end.
```

### Version Negotiation

```json
// Client announces capabilities
{
  "type": "hello",
  "supported_protocols": ["x3dh", "pqxdh"],
  "preferred_protocol": "pqxdh"
}

// Server responds with selected protocol
{
  "type": "welcome",
  "selected_protocol": "pqxdh",
  "server_version": "2.0.0"
}
```

---

## 7. Migration Strategy

### Phase A: Dual-Mode Server (Week 6-7)

1. Server accepts both X3DH and PQXDH key bundles
2. Server stores protocol version with each user's keys
3. Server returns appropriate bundle based on requester's capability

### Phase B: Client Upgrade (Week 7-8)

1. Release new client version with PQXDH support
2. Client generates PQXDH keys on first launch
3. Client uploads PQXDH bundle to server
4. Client still accepts X3DH messages from old clients

### Phase C: Transition Period (Months 1-6)

1. Both protocols coexist
2. New conversations prefer PQXDH
3. Existing sessions continue with current protocol
4. Monitor adoption metrics

### Phase D: X3DH Deprecation (Month 6+)

1. Warn users still on X3DH-only clients
2. Set deadline for X3DH sunset
3. Remove X3DH code paths (optional)

---

## 8. Testing Plan

### Unit Tests

```erlang
%% test/cryptic_pq_tests.erl
pqxdh_key_generation_test() ->
    Keys = cryptic_lib:generate_client_keys(pqxdh),
    ?assert(maps:is_key(pqkem_prekey_public, Keys)),
    ?assertEqual(1184, byte_size(maps:get(pqkem_prekey_public, Keys))),
    ?assertEqual(2400, byte_size(maps:get(pqkem_prekey_private, Keys))).

pqxdh_roundtrip_test() ->
    AliceKeys = cryptic_lib:generate_client_keys(pqxdh),
    BobKeys = cryptic_lib:generate_client_keys(pqxdh),
    BobBundle = cryptic_lib:export_public_bundle(BobKeys),
    
    {ok, AliceSecret, InitMsg} = cryptic_lib:perform_pqxdh_initiator(
        AliceKeys, BobBundle
    ),
    {ok, BobSecret} = cryptic_lib:perform_pqxdh_responder(
        BobKeys, InitMsg
    ),
    
    ?assertEqual(AliceSecret, BobSecret).

pqxdh_signature_verification_test() ->
    Keys = cryptic_lib:generate_client_keys(pqxdh),
    Bundle = cryptic_lib:export_public_bundle(Keys),
    
    ?assert(cryptic_lib:verify_pqkem_prekey(Bundle)),
    
    %% Tamper with signature
    TamperedBundle = Bundle#{pqkem_prekey_signature => crypto:strong_rand_bytes(64)},
    ?assertNot(cryptic_lib:verify_pqkem_prekey(TamperedBundle)).
```

### Integration Tests

```erlang
%% test/cryptic_pqxdh_integration_tests.erl
full_conversation_pqxdh_test() ->
    %% Start server
    {ok, _} = cryptic_server:start(),
    
    %% Alice and Bob connect with PQXDH
    {ok, Alice} = cryptic_client:connect(<<"alice">>, #{protocol => pqxdh}),
    {ok, Bob} = cryptic_client:connect(<<"bob">>, #{protocol => pqxdh}),
    
    %% Alice initiates PQXDH session with Bob
    {ok, _} = cryptic_client:send_message(Alice, <<"bob">>, <<"Hello Bob!">>),
    
    %% Bob receives and decrypts
    receive
        {message, <<"alice">>, <<"Hello Bob!">>} -> ok
    after 5000 ->
        ?assert(false)
    end.

mixed_protocol_test() ->
    %% Alice uses PQXDH, Bob uses X3DH
    {ok, Alice} = cryptic_client:connect(<<"alice">>, #{protocol => pqxdh}),
    {ok, Bob} = cryptic_client:connect(<<"bob">>, #{protocol => x3dh}),
    
    %% Should fall back to X3DH
    {ok, Protocol} = cryptic_client:send_message(Alice, <<"bob">>, <<"Hi">>),
    ?assertEqual(x3dh, Protocol).
```

### Performance Tests

```erlang
pqxdh_performance_test() ->
    %% Key generation benchmark
    {KeyGenTime, _} = timer:tc(fun() ->
        [cryptic_lib:generate_client_keys(pqxdh) || _ <- lists:seq(1, 100)]
    end),
    io:format("PQXDH key gen: ~p ms/key~n", [KeyGenTime / 100000]),
    
    %% Encapsulation benchmark
    {_, PrivKey} = crypto:generate_key(mlkem768, []),
    {PubKey, _} = crypto:generate_key(mlkem768, []),
    
    {EncapTime, _} = timer:tc(fun() ->
        [cryptic_pq:encapsulate(PubKey) || _ <- lists:seq(1, 1000)]
    end),
    io:format("ML-KEM encapsulate: ~p μs/op~n", [EncapTime / 1000]).
```

---

## 9. Security Considerations

### Cryptographic Choices

| Choice | Rationale |
|--------|-----------|
| **ML-KEM-768** | NIST Level 3 security, balance of size/security |
| **Hybrid approach** | Defense in depth; classical + PQ |
| **Ed25519 signatures** | Sign PQ prekeys for authenticity |
| **HKDF-SHA256** | Standard, well-analyzed KDF |

### Threat Model Updates

| Threat | X3DH | PQXDH |
|--------|------|-------|
| Classical MITM | ✅ Protected | ✅ Protected |
| Quantum key recovery | ❌ Vulnerable | ✅ Protected |
| Harvest-now-decrypt-later | ❌ Vulnerable | ✅ Protected |
| Implementation bugs | ⚠️ Risk | ⚠️ Higher risk (more code) |

### Implementation Security

1. **Constant-time operations**: OTP crypto uses OpenSSL's constant-time implementations
2. **Memory zeroing**: Ensure private keys are zeroed after use
3. **Side-channel resistance**: ML-KEM in OpenSSL 3.5+ is hardened
4. **Signature verification**: Always verify PQ prekey signatures before use

---

## 10. Timeline Estimate

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| **Phase 1**: Infrastructure | 2 weeks | `cryptic_pq.erl`, type specs |
| **Phase 2**: Key Generation | 1 week | PQXDH key bundle generation |
| **Phase 3**: Protocol | 2 weeks | PQXDH initiator/responder |
| **Phase 4**: Wire Protocol | 1 week | Message format updates |
| **Phase 5**: Storage | 1 week | Database schema, file format |
| **Phase 6**: Testing | 2 weeks | Unit, integration, performance tests |
| **Phase 7**: Migration | 1 week | Dual-mode server, client upgrade |
| **Total** | **10 weeks** | Full PQXDH implementation |

---

## Appendix A: OTP 28 ML-KEM API Reference

```erlang
%% Check availability
crypto:supports(kems).
%% => [mlkem512, mlkem768, mlkem1024]

%% Generate keypair
{PublicKey, PrivateKey} = crypto:generate_key(mlkem768, []).
%% PublicKey: 1184 bytes, PrivateKey: 2400 bytes

%% Encapsulate (sender creates shared secret + ciphertext)
{SharedSecret, Ciphertext} = crypto:encapsulate_key(mlkem768, PublicKey).
%% SharedSecret: 32 bytes, Ciphertext: 1088 bytes

%% Decapsulate (receiver recovers shared secret)
SharedSecret = crypto:decapsulate_key(mlkem768, PrivateKey, Ciphertext).
%% SharedSecret: 32 bytes
```

---

## Appendix B: References

1. [Signal PQXDH Specification](https://signal.org/docs/specifications/pqxdh/)
2. [NIST FIPS 203 - ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
3. [OTP 28 Crypto Documentation](https://www.erlang.org/doc/apps/crypto/)
4. [Hybrid Key Exchange in TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)

---

**Document Version**: 1.0  
**Last Updated**: December 2024  
**Author**: Cryptic Development Team
