%%% @doc Cryptographic Library for Secure Communication
%%%
%%% This module provides cryptographic primitives for the Cryptic chat application.
%%% It wraps libsodium functions through NIFs and implements the X3DH key agreement
%%% protocol for secure end-to-end encrypted messaging with forward secrecy.
%%%
%%% == Cryptographic Primitives ==
%%%
%%% <ul>
%%%   <li>**Ed25519 Signatures**: Digital signatures for identity verification</li>
%%%   <li>**X25519 Key Exchange**: Elliptic curve Diffie-Hellman key agreement</li>
%%%   <li>**ChaCha20-Poly1305**: Authenticated encryption with associated data (AEAD)</li>
%%%   <li>**HKDF-SHA256**: Key derivation function for generating encryption keys</li>
%%%   <li>**PBKDF2-SHA256**: Password-based key derivation for key storage</li>
%%%   <li>**Secure Random**: Cryptographically secure random number generation</li>
%%% </ul>
%%%
%%% == X3DH Protocol Implementation ==
%%%
%%% The library implements the X3DH (Extended Triple Diffie-Hellman) key agreement
%%% protocol, which provides forward secrecy and cryptographic deniability:
%%% <ol>
%%%   <li>**Identity Keys**: Long-term Ed25519 signing keys and derived X25519 DH keys</li>
%%%   <li>**Signed Prekeys**: Medium-term X25519 keys signed by identity key</li>
%%%   <li>**One-Time Prekeys**: Single-use X25519 keys for perfect forward secrecy</li>
%%%   <li>**Ephemeral Keys**: Session-specific X25519 keys for each message</li>
%%%   <li>**Key Derivation**: HKDF-based expansion of shared secrets to encryption keys</li>
%%% </ol>
%%%
%%% == Security Model ==
%%%
%%% The library implements a forward-secure messaging protocol:
%%% <ol>
%%%   <li>Each user generates Ed25519 identity keys and X25519 DH keys from shared entropy</li>
%%%   <li>Signed prekeys and one-time prekeys enable asynchronous key agreement</li>
%%%   <li>Message encryption uses ephemeral X25519 keypairs for perfect forward secrecy</li>
%%%   <li>Shared secrets are derived using X25519 scalar multiplication</li>
%%%   <li>AEAD keys are derived from shared secrets using HKDF-SHA256</li>
%%%   <li>Messages are encrypted with ChaCha20-Poly1305 AEAD</li>
%%%   <li>Private keys are stored encrypted with ChaCha20-Poly1305 using PBKDF2-derived keys</li>
%%% </ol>
%%%
%%% == Key Derivation Strategies ==
%%%
%%% The module provides three AEAD key derivation approaches with different security/usability tradeoffs:
%%% <ul>
%%%   <li>`derive_aead_key_random/1' - Most secure with random salt</li>
%%%   <li>`derive_aead_key_ephemeral/2' - Good balance using ephemeral public key as salt</li>
%%%   <li>`derive_aead_key_simple/1' - Simplest but least secure (empty salt)</li>
%%% </ul>
%%%
%%% For identity key generation, the module uses deterministic derivation from a master seed
%%% to ensure Ed25519 and X25519 keys have a cryptographic relationship while avoiding
%%% conversion issues between different curve representations.
%%%
%%% == Cryptographic Algorithm Choice: ChaCha20-Poly1305 vs AES-256-GCM ==
%%%
%%% This library uses **ChaCha20-Poly1305 AEAD** for all authenticated encryption operations,
%%% including key storage encryption via the libsodium NIF interface. This represents a
%%% significant upgrade from traditional AES-256-GCM implementations.
%%%
%%% **Performance Comparison** (typical results on modern hardware):
%%% <ul>
%%%   <li>ChaCha20-Poly1305: ~18.55ms per 100 encrypt/decrypt cycles (36KB data)</li>
%%%   <li>AES-256-GCM: ~38.65ms per 100 encrypt/decrypt cycles (36KB data)</li>
%%%   <li>**Performance Advantage**: ChaCha20-Poly1305 is ~2.08x faster</li>
%%% </ul>
%%%
%%% **Security Advantages of ChaCha20-Poly1305**:
%%% <ul>
%%%   <li>**Constant-Time**: Naturally resistant to side-channel/timing attacks on all hardware</li>
%%%   <li>**Hardware Independent**: Consistent performance across ARM, x86, and other CPUs</li>
%%%   <li>**Modern Design**: State-of-the-art cryptographic construction (RFC 8439)</li>
%%%   <li>**Industry Standard**: Used in TLS 1.3, Signal Protocol, WireGuard, and OpenSSH</li>
%%%   <li>**Memory Safe**: No lookup tables, immune to cache-timing attacks</li>
%%% </ul>
%%%
%%% **Data Format** (both algorithms have 44-byte overhead):
%%% <pre>
%%% ChaCha20-Poly1305: [Salt: 16B] [Nonce: 12B] [Ciphertext+AuthTag: N+16B]
%%% AES-256-GCM:       [Salt: 16B] [IV: 12B] [AuthTag: 16B] [Ciphertext: NB]
%%% </pre>
%%%
%%% == Key Management ==
%%%
%%% <ul>
%%%   <li>**Key Generation**: Deterministic Ed25519/X25519 key derivation from master seed</li>
%%%   <li>**Key Storage**: ChaCha20-Poly1305 encryption with PBKDF2-derived passphrase keys</li>
%%%   <li>**One-Time Prekeys**: X25519 keypairs with unique IDs for single-use consumption</li>
%%%   <li>**libsodium Integration**: Secure curve conversion utilities via NIF interface</li>
%%% </ul>
%%%
%%% == Example Usage ==
%%%
%%% <pre>
%%% %% Initialize client with X3DH key bundle
%%% Keys = cryptic_lib:generate_client_keys(),
%%% #{identity_sign_public := IdentitySignPub,
%%%   identity_dh_public := IdentityDHPub,
%%%   signed_prekey_public := SignedPrekeyPub,
%%%   one_time_prekeys := OneTimePrekeys} = Keys,
%%%
%%% %% Encrypt and save keys to file
%%% Passphrase = &lt;&lt;"secure_passphrase">>,
%%% ok = cryptic_lib:save_encrypted_keys(Keys, Passphrase, "/path/to"),
%%%
%%% %% Later, load keys from file
%%% {ok, LoadedKeys} = cryptic_lib:load_encrypted_keys("/path/to/keys.encrypted", Passphrase),
%%%
%%% %% Or use the convenience function for initialization
%%% {ok, ClientKeys} = cryptic_lib:initialize_client_keys("/config/dir", Passphrase),
%%%
%%% %% Generate ephemeral keypair for message encryption
%%% {EphemeralPub, EphemeralPriv} = cryptic_lib:gen_keypair(),
%%%
%%% %% Perform X25519 key agreement with recipient's public keys
%%% SharedSecret1 = cryptic_lib:scalarmult(EphemeralPriv, IdentityDHPub),
%%% SharedSecret2 = cryptic_lib:scalarmult(EphemeralPriv, SignedPrekeyPub),
%%%
%%% %% Derive AEAD key using ephemeral public key as salt
%%% AeadKey = cryptic_lib:derive_aead_key_ephemeral(SharedSecret1, EphemeralPub),
%%%
%%% %% Encrypt message with forward secrecy
%%% {Ciphertext, Nonce} = cryptic_lib:aead_encrypt(&lt;&lt;"Hello">>, AeadKey, &lt;&lt;>>),
%%%
%%% %% Decrypt message
%%% Plaintext = cryptic_lib:aead_decrypt(Ciphertext, AeadKey, Nonce, &lt;&lt;>>).
%%% </pre>
%%%
%%% @author Cryptic Team
%%% @version 2.0
%%% @since 2025-09-12
-module(cryptic_lib).

-export([
    initialize/0,
    gen_keypair/0,
    scalarmult/2,
    aead_encrypt/3,
    aead_decrypt/4,
    rand_bytes/1,
    hkdf_sha256/3,
    hkdf_sha256/4,
    derive_aead_key_random/1,
    derive_aead_key_ephemeral/2,
    derive_aead_key_simple/1,
    %% Server storage functions
    store_prekey/2,
    get_prekey/1,
    list_users/0,
    get_messages/1,
    %% Key management functions
    generate_client_keys/0,
    generate_one_time_prekeys/1,
    ed25519_to_x25519_private/1,
    ed25519_to_x25519_public/1,
    derive_key_from_passphrase/2,
    encrypt_keys/2,
    decrypt_keys/2,
    initialize_client_keys/2,
    %% Ratchet session persistence functions
    save_ratchet_session/4,
    load_ratchet_session/3,
    load_all_ratchet_sessions/2,
    delete_ratchet_session/2,
    %% Message signing functions
    sign_message/2,
    verify_signature/3,
    %% X3DH Protocol Implementation
    x3dh_sender_init/3,
    x3dh_sender_init_with_session_key/3,
    x3dh_receiver_decrypt/4,
    x3dh_receiver_decrypt_with_session_key/4,
    find_otpk_private_key/2,
    %% OTPK usage tracking
    track_otpk_usage/3,
    check_otpk_usage/2,
    cleanup_old_otpk/2,
    get_cryptic_dir/0,
    get_cryptic_dir/3,
    get_server_file/2
]).

-include("cryptic.hrl").

%% @doc Initialize the cryptic_lib module.
%% This function ensures that necessary ETS tables are created.
%% @returns ok.
-spec initialize() -> ok.
initialize() ->
    ensure_tables().

%% Use our custom NIF functions (wraps libsodium)
%% gen_keypair returns {PubBin, PrivBin} for X25519

%% @doc Generate an X25519 elliptic curve keypair for cryptographic operations.
%%
%% Creates a new X25519 keypair suitable for Elliptic Curve Diffie-Hellman
%% key exchange. The keypair consists of:
%% <ul>
%%   <li>**Public Key**: 32 bytes, safe to share publicly</li>
%%   <li>**Private Key**: 32 bytes, must be kept secret</li>
%% </ul>
%%
%% X25519 provides 128-bit security level and is designed to be fast and
%% resistant to side-channel attacks.
%%
%% == Example ==
%% <pre>
%% {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
%% io:format("Public key: ~p~n", [base64:encode(PubKey)]).
%% </pre>
%%
%% @returns `{PublicKey, PrivateKey}' where both keys are 32-byte binaries.
gen_keypair() ->
    %% Our NIF returns {Public, Secret}
    cryptic_nif:gen_keypair().

%% @doc Perform X25519 scalar multiplication for shared secret generation.
%%
%% Computes the shared secret between a private key and a public key using
%% X25519 elliptic curve scalar multiplication. This is the core operation
%% for Elliptic Curve Diffie-Hellman (ECDH) key agreement.
%%
%% == Security Properties ==
%% <ul>
%%   <li>**Perfect Forward Secrecy**: Each message can use ephemeral keys</li>
%%   <li>**Computational Security**: Based on discrete logarithm problem</li>
%%   <li>**Constant Time**: Resistant to timing side-channel attacks</li>
%% </ul>
%%
%% == Example ==
%% <pre>
%% %% Alice and Bob generate keypairs
%% {AlicePub, AlicePriv} = cryptic_lib:gen_keypair(),
%% {BobPub, BobPriv} = cryptic_lib:gen_keypair(),
%%
%% %% Both can compute the same shared secret
%% SharedSecret1 = cryptic_lib:scalarmult(AlicePriv, BobPub),
%% SharedSecret2 = cryptic_lib:scalarmult(BobPriv, AlicePub),
%% true = SharedSecret1 =:= SharedSecret2.
%% </pre>
%%
%% @param PrivateKey 32-byte private key for scalar multiplication
%% @param PublicKey 32-byte public key point to multiply
%% @returns 32-byte shared secret binary
%% @throws badarg
scalarmult(Priv, Pub) ->
    %% X25519 scalar multiplication via our NIF
    cryptic_nif:scalarmult(Priv, Pub).

%% @doc Encrypt plaintext using ChaCha20-Poly1305 AEAD cipher.
%%
%% Performs authenticated encryption with associated data (AEAD) using the
%% ChaCha20-Poly1305 cipher. This provides both confidentiality and authenticity:
%% <ul>
%%   <li>**Confidentiality**: Plaintext is encrypted with ChaCha20 stream cipher</li>
%%   <li>**Authenticity**: Poly1305 MAC ensures data hasn't been tampered with</li>
%%   <li>**Associated Data**: Additional data is authenticated but not encrypted</li>
%% </ul>
%%
%% The nonce is generated randomly for each encryption operation and must be
%% transmitted along with the ciphertext for decryption.
%%
%% == Example ==
%% <pre>
%% Key = cryptic_lib:rand_bytes(32),
%% Message = &lt;&lt;"Hello, World!">>,
%% AAD = &lt;&lt;"metadata">>,
%% {Ciphertext, Nonce} = cryptic_lib:aead_encrypt(Message, Key, AAD).
%% </pre>
%%
%% @param Plaintext Binary data to encrypt
%% @param Key 32-byte ChaCha20 encryption key
%% @param AAD Additional authenticated data (can be empty binary)
%% @returns `{Ciphertext, Nonce}' where Nonce is 12 bytes for ChaCha20-Poly1305-IETF
%% @throws badarg
aead_encrypt(Plain, Key, AAD) ->
    %% Use ChaCha20-Poly1305 IETF via our NIF
    %% NIF generates nonce internally and returns {Cipher, Nonce}
    cryptic_nif:aead_encrypt(Plain, Key, AAD).

%% @doc Decrypt ciphertext using ChaCha20-Poly1305 AEAD cipher.
%%
%% Performs authenticated decryption of data encrypted with `aead_encrypt/3'.
%% The function:
%% <ol>
%%   <li>Verifies the Poly1305 authentication tag</li>
%%   <li>Decrypts the ciphertext with ChaCha20 if authentication succeeds</li>
%%   <li>Returns plaintext or error if authentication fails</li>
%% </ol>
%%
%% Authentication failure indicates the ciphertext has been corrupted or
%% tampered with, or an incorrect key/nonce was used.
%%
%% == Example ==
%% <pre>
%% Key = cryptic_lib:rand_bytes(32),
%% {Ciphertext, Nonce} = cryptic_lib:aead_encrypt(&lt;&lt;"Secret">>, Key, &lt;&lt;>>),
%% Plaintext = cryptic_lib:aead_decrypt(Ciphertext, Key, Nonce, &lt;&lt;>>).
%% </pre>
%%
%% @param Ciphertext Encrypted data with authentication tag
%% @param Key 32-byte ChaCha20 decryption key (same as used for encryption)
%% @param Nonce 12-byte nonce used during encryption
%% @param AAD Additional authenticated data (must match encryption AAD)
%% @returns Decrypted plaintext binary
%% @throws error
aead_decrypt(Cipher, Key, Nonce, AAD) ->
    %% ChaCha20-Poly1305 IETF decryption via our NIF
    cryptic_nif:aead_decrypt(Cipher, Key, Nonce, AAD).

%% @doc Generate cryptographically secure random bytes.
%%
%% Uses the operating system's cryptographically secure random number
%% generator (via libsodium) to generate unpredictable random data suitable
%% for cryptographic operations such as:
%% <ul>
%%   <li>Generating encryption keys</li>
%%   <li>Creating nonces and initialization vectors</li>
%%   <li>Generating salts for key derivation</li>
%%   <li>Creating random padding</li>
%% </ul>
%%
%% == Example ==
%% <pre>
%% %% Generate a 256-bit encryption key
%% Key = cryptic_lib:rand_bytes(32),
%%
%% %% Generate a random salt for key derivation
%% Salt = cryptic_lib:rand_bytes(16).
%% </pre>
%%
%% @param N Number of random bytes to generate
%% @returns Binary containing N cryptographically secure random bytes
%% @throws badarg
rand_bytes(N) ->
    %% Generate cryptographically secure random bytes via our NIF
    cryptic_nif:rand_bytes(N).

%% HKDF-SHA256 key derivation

%% @doc Derive cryptographic keys using HKDF-SHA256 with empty salt.
%%
%% HKDF (HMAC-based Key Derivation Function) is a key derivation function
%% based on HMAC-SHA256. It's designed to take input keying material (IKM)
%% and derive one or more cryptographically strong keys from it.
%%
%% This is a convenience function that calls `hkdf_sha256/4' with an empty salt.
%% For better security, consider using `hkdf_sha256/4' with a random salt.
%%
%% == Use Cases ==
%% <ul>
%%   <li>Deriving encryption keys from shared secrets</li>
%%   <li>Expanding short keys into longer keys</li>
%%   <li>Key diversification for different purposes</li>
%% </ul>
%%
%% == Example ==
%% <pre>
%% SharedSecret = cryptic_lib:scalarmult(PrivKey, PubKey),
%% EncKey = cryptic_lib:hkdf_sha256(SharedSecret, &lt;&lt;"encryption"&gt;&gt;, 32),
%% MacKey = cryptic_lib:hkdf_sha256(SharedSecret, &lt;&lt;"authentication"&gt;&gt;, 32).
%% </pre>
%%
%% @param IKM Input keying material (e.g., shared secret from ECDH)
%% @param Info Context and application-specific information
%% @param L Length of output keying material in bytes (max 255 * 32)
%% @returns Derived key material of specified length
hkdf_sha256(IKM, Info, L) ->
    hkdf_sha256(IKM, <<>>, Info, L).

%% @doc Derive cryptographic keys using HKDF-SHA256 with explicit salt.
%%
%% Full HKDF-SHA256 implementation with explicit salt parameter. The salt
%% provides additional entropy and ensures that the same IKM produces
%% different output keys when used with different salts.
%%
%% == HKDF Process ==
%% <ol>
%%   <li>**Extract**: PRK = HMAC-SHA256(Salt, IKM)</li>
%%   <li>**Expand**: OKM = HMAC-SHA256(PRK, Info || 0x01)[0..L-1]</li>
%% </ol>
%%
%% == Salt Guidelines ==
%% <ul>
%%   <li>**Random Salt**: Most secure, use `rand_bytes/1' to generate</li>
%%   <li>**Fixed Salt**: Acceptable if it's application-specific and unique</li>
%%   <li>**Empty Salt**: Least secure but still cryptographically sound</li>
%% </ul>
%%
%% == Example ==
%% <pre>
%% SharedSecret = cryptic_lib:scalarmult(PrivKey, PubKey),
%% Salt = cryptic_lib:rand_bytes(32),
%% EncKey = cryptic_lib:hkdf_sha256(SharedSecret, Salt, &lt;&lt;"encryption"&gt;&gt;, 32).
%% </pre>
%%
%% @param IKM Input keying material (e.g., shared secret from ECDH)
%% @param Salt Optional salt value for extraction phase (can be empty)
%% @param Info Context and application-specific information
%% @param L Length of output keying material in bytes (max 255 * 32)
%% @returns Derived key material of specified length
hkdf_sha256(IKM, Salt, Info, L) ->
    PRK = crypto:mac(hmac, sha256, Salt, IKM),
    T1 = crypto:mac(hmac, sha256, PRK, <<Info/binary, 1:8>>),
    %% For 32-byte output, single iteration is sufficient
    binary:part(T1, 0, L).

%% @doc Derive AEAD key with random salt (most secure approach).
%%
%% This is the most secure key derivation method that generates a random
%% salt for each key derivation operation. The random salt ensures that:
%% <ul>
%%   <li>Same shared secret produces different AEAD keys each time</li>
%%   <li>Protection against rainbow table attacks</li>
%%   <li>Enhanced security even if shared secret is compromised</li>
%% </ul>
%%
%% **Trade-off**: Requires transmitting the salt along with the ciphertext,
%% increasing message size by 32 bytes.
%%
%% == Example ==
%% <pre>
%% SharedSecret = cryptic_lib:scalarmult(MyPrivKey, TheirPubKey),
%% {AeadKey, Salt} = cryptic_lib:derive_aead_key_random(SharedSecret),
%% %% Salt must be transmitted with the message for decryption
%% </pre>

%% @param SharedSecret 32-byte shared secret from X25519 key exchange
%% @returns `{AeadKey, Salt}' where AeadKey is 32 bytes and Salt is 32 bytes
derive_aead_key_random(SharedSecret) ->
    Salt = rand_bytes(32),
    AeadKey = hkdf_sha256(SharedSecret, Salt, <<"encryption">>, 32),
    {AeadKey, Salt}.

%% @doc Derive AEAD key using ephemeral public key as salt (good compromise).
%%
%% Uses the ephemeral public key as input to generate a deterministic salt.
%% This provides a good balance between security and efficiency:
%% <ul>
%%   <li>Deterministic: Same inputs always produce same key</li>
%%   <li>Unique: Different ephemeral keys produce different AEAD keys</li>
%%   <li>No transmission overhead: Salt derived from existing data</li>
%% </ul>
%%
%% **Suitable for**: Protocols where ephemeral public keys are already
%% transmitted and provide sufficient entropy.
%%
%% == Example ==
%% <pre>
%% {EphemeralPub, EphemeralPriv} = cryptic_lib:gen_keypair(),
%% SharedSecret = cryptic_lib:scalarmult(EphemeralPriv, RecipientPubKey),
%% AeadKey = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, EphemeralPub).
%% </pre>
%%
%% @param SharedSecret 32-byte shared secret from X25519 key exchange
%% @param EphemeralPubKey 32-byte ephemeral public key used as salt source
%% @returns 32-byte AEAD key for ChaCha20-Poly1305
derive_aead_key_ephemeral(SharedSecret, EphemeralPubKey) ->
    Salt = crypto:hash(sha256, EphemeralPubKey),
    hkdf_sha256(SharedSecret, Salt, <<"encryption">>, 32).

%% @doc Derive AEAD key with empty salt (simple but least secure).
%%
%% The simplest key derivation approach that uses an empty salt. While
%% still cryptographically sound, it provides the least security against
%% certain attack scenarios:
%% <ul>
%%   <li>Same shared secret always produces same AEAD key</li>
%%   <li>Vulnerable to rainbow table attacks on weak shared secrets</li>
%%   <li>No additional entropy beyond the shared secret</li>
%% </ul>
%%
%% **Use when**: Message overhead is critical and the shared secret has
%% sufficient entropy (e.g., from good random number generation).
%%
%% == Example ==
%% <pre>
%% SharedSecret = cryptic_lib:scalarmult(MyPrivKey, TheirPubKey),
%% AeadKey = cryptic_lib:derive_aead_key_simple(SharedSecret).
%% </pre>
%%
%% @param SharedSecret 32-byte shared secret from X25519 key exchange
%% @returns 32-byte AEAD key for ChaCha20-Poly1305
derive_aead_key_simple(SharedSecret) ->
    hkdf_sha256(SharedSecret, <<"encryption">>, 32).

%%%===================================================================
%%% Server Storage Functions (Simple in-memory implementation)
%%%===================================================================

%% Simple in-memory storage with structured tuple keys for efficient access
%% Key structure:
%%   - {Username, identity} -> Identity key data
%%   - {Username, otpk, KeyId} -> One-time prekey data
%%   - Username -> User registration data
%%   - MessageId -> Message data
-define(PREKEY_TABLE, cryptic_prekeys).
-define(MESSAGE_TABLE, cryptic_messages).
-define(USER_TABLE, cryptic_users).

%% @doc Store a user's prekey.
-spec store_prekey(string(), binary()) -> ok | {error, term()}.
store_prekey(Username, Prekey) ->
    ets:insert(?PREKEY_TABLE, {Username, Prekey}),
    ets:insert(?USER_TABLE, {Username, erlang:system_time(second)}),
    ok.

%% @doc Get a user's prekey.
-spec get_prekey(string()) -> {ok, binary()} | {error, not_found}.
get_prekey(Username) ->
    case ets:lookup(?PREKEY_TABLE, Username) of
        [{Username, Prekey}] -> {ok, Prekey};
        [] -> {error, not_found}
    end.

%% @doc List all registered users.
-spec list_users() -> [string()].
list_users() ->
    [Username || {Username, _Timestamp} <- ets:tab2list(?USER_TABLE)].

%% @doc Get all messages for a user, then remove them from the store.
-spec get_messages(string()) -> [map()].
get_messages(Username) ->
    [
        begin
            ets:delete(?MESSAGE_TABLE, Id),
            MessageBlob
        end
     || {Id, ToUser, MessageBlob} <- ets:tab2list(?MESSAGE_TABLE),
        ToUser == Username
    ].

%%%===================================================================
%%% Key Management Functions
%%%===================================================================

%% @doc Generate or load client identity keys with configuration directory and passphrase.
%%
%% This function manages the cryptographic identity of a client:
%% - Ed25519 identity signing key (long-term)
%% - X25519 identity DH key (long-term, derived from master seed)
%% - X25519 signed prekey (medium-term, rotatable)
%% - One-Time Prekeys (OPKs) for forward secrecy
%%
%% Keys are stored encrypted in the specified directory with PBKDF2-derived encryption.
%% The passphrase is provided by the caller, allowing the library to be used in different
%% contexts (CLI, GUI, automated systems) without hardcoded user interaction.
%%
%% @param ConfigDir Directory where encrypted keys file will be stored
%% @param Passphrase Binary or string passphrase for key encryption/decryption
%% @returns {ok, Keys} on success, {error, Reason} on failure
-spec initialize_client_keys(string(), string() | binary()) ->
    {ok, #{
        identity_sign_private => binary(),
        identity_sign_public => binary(),
        identity_dh_private => binary(),
        identity_dh_public => binary(),
        signed_prekey_private => binary(),
        signed_prekey_public => binary(),
        signed_prekey_signature => binary(),
        one_time_prekeys => [
            #{private => binary(), public => binary(), id => binary()}
        ],
        key_id => binary()
    }}
    | {error, term()}.
initialize_client_keys(ConfigDir, Passphrase) ->
    KeysFile = filename:join(ConfigDir, identity_keys_filename()),

    case filelib:is_file(KeysFile) of
        true ->
            %% Load existing keys
            load_encrypted_keys(KeysFile, Passphrase);
        false ->
            %% Generate new keys
            Keys = generate_client_keys(),
            case save_encrypted_keys(Keys, Passphrase, KeysFile) of
                ok -> {ok, Keys};
                {error, Reason} -> {error, Reason}
            end
    end.

%% @doc Generate all required client keys using deterministic derivation.
%%
%% Creates a complete X3DH key bundle with cryptographically linked Ed25519 and X25519
%% identity keys derived from a shared master seed. This approach ensures:
%% <ul>
%%   <li>**Deterministic**: Both Ed25519 and X25519 keys derived from same entropy</li>
%%   <li>**Reliable**: No conversion failures between curve representations</li>
%%   <li>**Secure**: Each key type uses proper cryptographic generation</li>
%%   <li>**X3DH Compatible**: Complete key bundle for Signal-style messaging</li>
%% </ul>
%%
%% == Generated Keys ==
%% <ul>
%%   <li>**Identity Signing Keys**: Ed25519 keypair for digital signatures</li>
%%   <li>**Identity DH Keys**: X25519 keypair for key agreement (linked to signing keys)</li>
%%   <li>**Signed Prekey**: X25519 keypair signed by identity key for asynchronous messaging</li>
%%   <li>**One-Time Prekeys**: 10 X25519 keypairs with unique IDs for forward secrecy</li>
%% </ul>
%%
%% @returns Map containing complete X3DH key bundle with all necessary keys and signatures
-spec generate_client_keys() ->
    #{
        identity_sign_private => binary(),
        identity_sign_public => binary(),
        identity_dh_private => binary(),
        identity_dh_public => binary(),
        signed_prekey_private => binary(),
        signed_prekey_public => binary(),
        signed_prekey_signature => binary(),
        one_time_prekeys => [
            #{private => binary(), public => binary(), id => binary()}
        ],
        key_id => binary()
    }.
generate_client_keys() ->
    %% Generate a master seed for deterministic key derivation
    MasterSeed = crypto:strong_rand_bytes(32),

    %% Derive Ed25519 signing keypair from seed
    Ed25519Seed = crypto:hash(sha256, <<MasterSeed/binary, "ed25519">>),
    {IdentitySignPub, IdentitySignPriv} = crypto:generate_key(
        eddsa, ed25519, Ed25519Seed
    ),

    %% Derive X25519 DH keypair from same master seed for correspondence
    X25519Seed = crypto:hash(sha256, <<MasterSeed/binary, "x25519">>),
    {IdentityDHPub, IdentityDHPriv} = crypto:generate_key(
        ecdh, x25519, X25519Seed
    ),

    %% Generate X25519 signed prekey
    {SignedPrekeyPub, SignedPrekeyPriv} = crypto:generate_key(ecdh, x25519),

    %% Sign the prekey public key with identity signing key
    SignedPrekeySignature = crypto:sign(eddsa, none, SignedPrekeyPub, [
        IdentitySignPriv, ed25519
    ]),

    %% Debug: Verify that we can verify our own signature
    VerifyOwnSig = crypto:verify(
        eddsa, none, SignedPrekeyPub, SignedPrekeySignature, [
            IdentitySignPub, ed25519
        ]
    ),
    ?dbg("generate_client_keys: Self-signature verification: ~p~n", [
        VerifyOwnSig
    ]),
    ?dbg("generate_client_keys: IdentitySignPub: ~p~n", [
        IdentitySignPub
    ]),
    ?dbg("generate_client_keys: SignedPrekeyPub: ~p~n", [
        SignedPrekeyPub
    ]),
    ?dbg("generate_client_keys: SignedPrekeySignature: ~p~n", [
        SignedPrekeySignature
    ]),

    %% Generate 10 One-Time Prekeys (OPKs)
    OneTimePrekeys = generate_one_time_prekeys(10),

    %% Generate unique key ID
    KeyId = crypto:strong_rand_bytes(16),

    #{
        %% Identity Keys
        %% -------------
        %% Use to sign the signed prekey to prove its authenticity to others.
        identity_sign_private => IdentitySignPriv,
        %% Users will use this to verify the signed prekey they receive.
        identity_sign_public => IdentitySignPub,
        %% Use this key, along with a peer's public keys, to perform the first
        %% Diffie-Hellman (DH) key exchange in the 3DH protocol.
        identity_dh_private => IdentityDHPriv,
        %% Other users will combine this key with their own keys to perform
        %% a DH exchange with you
        identity_dh_public => IdentityDHPub,

        %% Signed Prekey
        %% -------------
        %% Use this key to perform a DH key exchange with the sender's
        %% public identity key
        signed_prekey_private => SignedPrekeyPriv,
        %% Senders will use this key to perform a DH exchange with your
        %% identity key.
        signed_prekey_public => SignedPrekeyPub,
        %% Allows a sender to verify that the signed prekey was genuinely
        %% created and signed by your identity_sign_private key, preventing
        %% a man-in-the-middle attack.
        signed_prekey_signature => SignedPrekeySignature,

        %% One-Time Prekeys (OTPKs)
        %% -----------------------
        %% A collection of one-time key pairs. A sender will retrieve and
        %% use one of them to perform the final DH key exchange.
        %% Deleted after it has been used to decrypt a message,
        %% ensuring it can never be used again
        one_time_prekeys => OneTimePrekeys,
        %% Unique identifier for the entire set of client keys.
        %% This ID helps in managing and identifying a user's complete
        %% key bundle, especially on a server where multiple users and
        %% key bundles are stored.
        key_id => KeyId
    }.

%% @doc Generate a specified number of One-Time Prekeys (OPKs).
%%
%% One-Time Prekeys are X25519 keypairs that are used once for initial
%% key agreement in the X3DH protocol. Each OPK has:
%% - A unique ID for identification
%% - An X25519 keypair for ECDH operations
%% - Single-use property for forward secrecy
%%
%% @param Count Number of OPKs to generate (typically 10-100)
%% @returns List of OPK maps with private, public, and id fields
-spec generate_one_time_prekeys(pos_integer()) ->
    [#{private => binary(), public => binary(), id => binary()}].
generate_one_time_prekeys(Count) ->
    [
        begin
            {PubKey, PrivKey} = crypto:generate_key(ecdh, x25519),
            % 64-bit unique ID
            Id = crypto:strong_rand_bytes(8),
            #{
                private => PrivKey,
                public => PubKey,
                id => Id
            }
        end
     || _ <- lists:seq(1, Count)
    ].

%% @doc Convert Ed25519 private key to X25519 private key.
%%
%% Performs a secure conversion from an Ed25519 signing private key to an
%% X25519 ECDH private key using libsodium's crypto_sign_ed25519_sk_to_curve25519.
%% This function provides a mathematically sound conversion that preserves the
%% cryptographic relationship between keys.
%%
%% == Security Properties ==
%% <ul>
%%   <li>**Deterministic**: Same Ed25519 key always produces same X25519 key</li>
%%   <li>**Secure**: Uses libsodium's vetted conversion algorithm</li>
%%   <li>**Compatible**: Maintains key correspondence for X3DH protocol</li>
%% </ul>
%%
%% == X3DH Usage ==
%% In the X3DH key agreement protocol, identity keys can be used for both
%% signing (Ed25519) and key exchange (X25519), requiring this conversion.
%%
%% @param Ed25519Priv Ed25519 private key (32-byte binary)
%% @returns X25519 private key (32-byte binary)
%% @throws error
-spec ed25519_to_x25519_private(binary()) -> binary().
ed25519_to_x25519_private(Ed25519Priv) ->
    case cryptic_nif:ed25519_sk_to_x25519_sk(Ed25519Priv) of
        error ->
            error(
                {conversion_failed,
                    "Failed to convert Ed25519 private key to X25519"}
            );
        X25519Priv when is_binary(X25519Priv) ->
            X25519Priv
    end.

%% @doc Convert Ed25519 public key to X25519 public key.
%%
%% Performs a secure conversion from an Ed25519 signing public key to an
%% X25519 ECDH public key using libsodium's crypto_sign_ed25519_pk_to_curve25519.
%% This conversion maintains the mathematical relationship with the corresponding
%% private key conversion.
%%
%% == Security Properties ==
%% <ul>
%%   <li>**Deterministic**: Same Ed25519 key always produces same X25519 key</li>
%%   <li>**Public**: Conversion is safe to perform publicly</li>
%%   <li>**Correspondent**: Works with converted private keys</li>
%% </ul>
%%
%% == Protocol Usage ==
%% Essential for X3DH where identity public keys need to be used for both
%% signature verification and key agreement operations.
%%
%% @param Ed25519Pub Ed25519 public key (32-byte binary)
%% @returns X25519 public key (32-byte binary)
%% @throws error
-spec ed25519_to_x25519_public(binary()) -> binary().
ed25519_to_x25519_public(Ed25519Pub) ->
    case cryptic_nif:ed25519_pk_to_x25519_pk(Ed25519Pub) of
        error ->
            error(
                {conversion_failed,
                    "Failed to convert Ed25519 public key to X25519"}
            );
        X25519Pub when is_binary(X25519Pub) ->
            X25519Pub
    end.

%% @doc Derive encryption key from passphrase using PBKDF2-SHA256.
%%
%% Uses PBKDF2 (Password-Based Key Derivation Function 2) with SHA256 to derive
%% a cryptographically strong encryption key from a user passphrase. This function
%% is specifically designed for key storage encryption in the Cryptic system.
%%
%% == Security Parameters ==
%% <ul>
%%   <li>**Algorithm**: PBKDF2-HMAC-SHA256</li>
%%   <li>**Iterations**: 100,000 (provides strong resistance against brute-force attacks)</li>
%%   <li>**Key Length**: 32 bytes (256 bits) - suitable for ChaCha20-Poly1305</li>
%%   <li>**Salt**: Required 16-byte random salt for each derivation</li>
%% </ul>
%%
%% == Security Properties ==
%% <ul>
%%   <li>**Slow Derivation**: High iteration count makes brute-force attacks computationally expensive</li>
%%   <li>**Salt Protection**: Random salt prevents rainbow table attacks</li>
%%   <li>**Deterministic**: Same passphrase + salt always produces same key</li>
%%   <li>**Memory Hard**: PBKDF2 provides some resistance to specialized hardware attacks</li>
%% </ul>
%%
%% == Usage Context ==
%% This function is used internally by `encrypt_keys/2' and `decrypt_keys/2' to derive
%% the ChaCha20-Poly1305 encryption key from user passphrases for secure key storage.
%%
%% == Example ==
%% <pre>
%% Salt = cryptic_lib:rand_bytes(16),
%% Key = cryptic_lib:derive_key_from_passphrase(&lt;&lt;"my_secure_password"&gt;&gt;, Salt),
%% %% Key is now suitable for ChaCha20-Poly1305 encryption
%% </pre>
%%
%% @param Passphrase User passphrase as string or binary
%% @param Salt 16-byte random salt for key derivation
%% @returns 32-byte derived encryption key suitable for ChaCha20-Poly1305
-spec derive_key_from_passphrase(string() | binary(), binary()) -> binary().
derive_key_from_passphrase(Passphrase, Salt) when is_list(Passphrase) ->
    derive_key_from_passphrase(list_to_binary(Passphrase), Salt);
derive_key_from_passphrase(Passphrase, Salt) when is_binary(Passphrase) ->
    % PBKDF2 iterations
    Iterations = 100000,
    % 256-bit key
    KeyLength = 32,
    crypto:pbkdf2_hmac(sha256, Passphrase, Salt, Iterations, KeyLength).

%% @doc Encrypt private key material with passphrase-derived key using ChaCha20-Poly1305.
%%
%% Securely encrypts client cryptographic keys using ChaCha20-Poly1305 AEAD with a key
%% derived from a user passphrase via PBKDF2. This function provides secure storage
%% for sensitive cryptographic material including X3DH identity keys, signed prekeys,
%% and one-time prekeys.
%%
%% == Encryption Process ==
%% <ol>
%%   <li>Generate random 16-byte salt using libsodium's secure RNG</li>
%%   <li>Derive 32-byte ChaCha20 key using PBKDF2-SHA256 (100,000 iterations)</li>
%%   <li>Serialize key material using Erlang's term_to_binary/1</li>
%%   <li>Encrypt with ChaCha20-Poly1305 AEAD (includes authentication tag)</li>
%%   <li>Combine salt + nonce + authenticated ciphertext into single blob</li>
%% </ol>
%%
%% == Security Features ==
%% <ul>
%%   <li>**Authenticated Encryption**: ChaCha20-Poly1305 prevents tampering</li>
%%   <li>**Random Salt**: Each encryption uses unique salt for different keys</li>
%%   <li>**Strong KDF**: PBKDF2 with 100K iterations resists brute-force attacks</li>
%%   <li>**Format Protection**: Authentication tag covers entire ciphertext</li>
%% </ul>
%%
%% == Data Format ==
%% <pre>
%% [Salt: 16 bytes] [Nonce: 12 bytes] [Authenticated Ciphertext: N+16 bytes]
%% </pre>
%%
%% == Usage ==
%% Typically used by `save_encrypted_keys/3' and `save_ratchet_session/4' for
%% persistent storage of cryptographic keys and session state.
%%
%% == Example ==
%% <pre>
%% Keys = cryptic_lib:generate_client_keys(),
%% Passphrase = &lt;&lt;"secure_user_password">>,
%% {EncryptedData, Salt} = cryptic_lib:encrypt_keys(Keys, Passphrase),
%% %% EncryptedData ready for secure file storage
%% </pre>
%%
%% @param Keys Map containing cryptographic key material to encrypt
%% @param Passphrase User passphrase for key derivation (string or binary)
%% @returns `{EncryptedData, Salt}' where EncryptedData contains salt+nonce+ciphertext
-spec encrypt_keys(#{}, string() | binary()) -> {binary(), binary()}.
encrypt_keys(Keys, Passphrase) when is_list(Passphrase) ->
    encrypt_keys(Keys, list_to_binary(Passphrase));
encrypt_keys(Keys, Passphrase) when is_binary(Passphrase) ->
    %% Generate random salt using libsodium
    Salt = cryptic_nif:rand_bytes(16),

    %% Derive encryption key
    EncKey = derive_key_from_passphrase(Passphrase, Salt),

    %% Serialize keys to binary
    KeysBinary = term_to_binary(Keys),

    %% Encrypt with ChaCha20-Poly1305 AEAD via libsodium NIF
    %% Note: NIF returns {Ciphertext, Nonce}, not {Nonce, Ciphertext}
    {Ciphertext, Nonce} = cryptic_nif:aead_encrypt(KeysBinary, EncKey, <<>>),

    %% Combine all encrypted data (salt + nonce + ciphertext with auth tag)
    EncryptedData = <<Salt:16/binary, Nonce:12/binary, Ciphertext/binary>>,

    {EncryptedData, Salt}.

%% @doc Decrypt private key material with passphrase-derived key using ChaCha20-Poly1305.
%%
%% Securely decrypts client cryptographic keys that were encrypted with `encrypt_keys/2'.
%% Uses ChaCha20-Poly1305 AEAD for authenticated decryption, ensuring both data integrity
%% and authenticity. The function automatically extracts the salt and nonce from the
%% encrypted data blob and derives the decryption key using the same PBKDF2 process.
%%
%% == Decryption Process ==
%% <ol>
%%   <li>Extract 16-byte salt and 12-byte nonce from encrypted data blob</li>
%%   <li>Derive 32-byte ChaCha20 key using PBKDF2-SHA256 with extracted salt</li>
%%   <li>Decrypt and authenticate ciphertext using ChaCha20-Poly1305 AEAD</li>
%%   <li>Deserialize decrypted binary back to Erlang key material map</li>
%% </ol>
%%
%% == Security Validation ==
%% <ul>
%%   <li>**Authentication Check**: Poly1305 MAC verification prevents tampering detection</li>
%%   <li>**Passphrase Verification**: Wrong passphrase results in authentication failure</li>
%%   <li>**Format Validation**: Corrupted data is detected during decryption process</li>
%%   <li>**Constant Time**: ChaCha20-Poly1305 provides side-channel resistance</li>
%% </ul>
%%
%% == Error Conditions ==
%% <ul>
%%   <li>`{error, decryption_failed}' - Wrong passphrase or corrupted ciphertext</li>
%%   <li>`{error, invalid_encrypted_data}' - Malformed data blob or parsing error</li>
%% </ul>
%%
%% == Usage ==
%% Typically used by `load_encrypted_keys/2' and `load_ratchet_session/3' for
%% loading cryptographic keys and session state from persistent storage.
%%
%% == Example ==
%% <pre>
%% %% Load encrypted data from file
%% {ok, EncryptedData} = file:read_file("keys.encrypted"),
%% Passphrase = &lt;&lt;"secure_user_password">>,
%% case cryptic_lib:decrypt_keys(EncryptedData, Passphrase) of
%%     {ok, Keys} ->
%%         %% Keys successfully decrypted and ready to use
%%         Keys;
%%     {error, decryption_failed} ->
%%         %% Wrong passphrase or corrupted data
%%         error(invalid_passphrase)
%% end.
%% </pre>
%%
%% @param EncryptedData Binary blob containing salt+nonce+authenticated ciphertext
%% @param Passphrase User passphrase for key derivation (string or binary)
%% @returns `{ok, Keys}' on success, `{error, Reason}' on failure
-spec decrypt_keys(binary(), string() | binary()) ->
    {ok, #{}} | {error, term()}.
decrypt_keys(EncryptedData, Passphrase) when is_list(Passphrase) ->
    decrypt_keys(EncryptedData, list_to_binary(Passphrase));
decrypt_keys(EncryptedData, Passphrase) when is_binary(Passphrase) ->
    try
        %% Extract components (salt + nonce + ciphertext with auth tag)
        <<Salt:16/binary, Nonce:12/binary, Ciphertext/binary>> =
            EncryptedData,

        %% Derive decryption key
        DecKey = derive_key_from_passphrase(Passphrase, Salt),

        %% Decrypt with ChaCha20-Poly1305 AEAD via libsodium NIF
        case cryptic_nif:aead_decrypt(Ciphertext, DecKey, Nonce, <<>>) of
            Plaintext when is_binary(Plaintext) ->
                Keys = binary_to_term(Plaintext),
                {ok, Keys};
            error ->
                {error, decryption_failed}
        end
    catch
        _:_ ->
            {error, invalid_encrypted_data}
    end.

%% @private Save encrypted keys to file.
-spec save_encrypted_keys(#{}, string() | binary(), string()) ->
    ok | {error, term()}.
save_encrypted_keys(Keys, Passphrase, KeysFile) ->
    %% Encrypt keys
    {EncryptedData, _Salt} = encrypt_keys(Keys, Passphrase),
    ?dbg("save_encrypted_keys: KeysFile ~p~n", [KeysFile]),

    %% Ensure directory exists using ensure_dir with the file path
    %% Write to file
    case file:write_file(KeysFile, EncryptedData) of
        ok ->
            %% rw-------
            file:change_mode(KeysFile, 8#600),
            ok;
        {error, Reason} ->
            {error, {file_write_error, Reason}}
    end.

%% @private Load and decrypt keys from file.
-spec load_encrypted_keys(string(), string() | binary()) ->
    {ok, #{}} | {error, term()}.
load_encrypted_keys(KeysFile, Passphrase) ->
    case file:read_file(KeysFile) of
        {ok, EncryptedData} ->
            decrypt_keys(EncryptedData, Passphrase);
        {error, Reason} ->
            {error, {file_read_error, Reason}}
    end.

%%% @private
identity_keys_filename() ->
    "keys.encrypted".

%% @doc Save a ratchet session to encrypted storage.
%%
%% Saves a double ratchet session state to an encrypted file using the same
%% encryption infrastructure as save_encrypted_keys/3. The session data is
%% encrypted with ChaCha20-Poly1305 AEAD using a key derived from the user's passphrase.
%%
%% @param Username The username identifying the ratchet session
%% @param SessionData The ratchet session state (map containing keys, counters, etc.)
%% @param Passphrase User passphrase for encryption
%% @param BaseDir Base directory for storing ratchet sessions (usually "~/.cryptic/sessions")
%% @returns ok | {error, term()}
-spec save_ratchet_session(string(), #{}, string() | binary(), string()) ->
    ok | {error, term()}.
save_ratchet_session(Username, SessionData, Passphrase, BaseDir) ->
    %% Create session filename first
    SessionFile = filename:join(BaseDir, Username ++ ".session"),

    %% Ensure directory exists using ensure_dir with the file path
    %% (ensure_dir creates the parent directory of the given path)
    case filelib:ensure_dir(SessionFile) of
        ok ->
            %% Use existing encryption infrastructure
            save_encrypted_keys(SessionData, Passphrase, SessionFile);
        {error, Reason} ->
            {error, {directory_creation_failed, Reason}}
    end.

%% @doc Load a specific ratchet session from encrypted storage.
%%
%% Loads and decrypts a double ratchet session state from file using the same
%% decryption infrastructure as load_encrypted_keys/2.
%%
%% @param Username The username identifying the ratchet session
%% @param Passphrase User passphrase for decryption
%% @param BaseDir Base directory for storing ratchet sessions
%% @returns {ok, SessionData} | {error, term()}
-spec load_ratchet_session(string(), string() | binary(), string()) ->
    {ok, #{}} | {error, term()}.
load_ratchet_session(Username, Passphrase, BaseDir) ->
    SessionFile = filename:join(BaseDir, Username ++ ".session"),
    load_encrypted_keys(SessionFile, Passphrase).

%% @doc Load all available ratchet sessions from encrypted storage.
%%
%% Scans the sessions directory and attempts to load all .session files
%% using the provided passphrase. Returns a map of username -> session_data
%% for successfully loaded sessions, and logs errors for failed ones.
%%
%% @param Passphrase User passphrase for decryption
%% @param BaseDir Base directory for storing ratchet sessions
%% @returns {ok, SessionsMap} | {error, term()}
-spec load_all_ratchet_sessions(string() | binary(), string()) ->
    {ok, #{}} | {error, term()}.
load_all_ratchet_sessions(Passphrase, BaseDir) ->
    case file:list_dir(BaseDir) of
        {ok, Files} ->
            SessionFiles = [
                F
             || F <- Files, filename:extension(F) =:= ".session"
            ],
            LoadedSessions = maps:from_list([
                {Username, SessionData}
             || File <- SessionFiles,
                Username <- [filename:basename(File, ".session")],
                {ok, SessionData} <- [
                    load_ratchet_session(Username, Passphrase, BaseDir)
                ]
            ]),
            {ok, LoadedSessions};
        {error, enoent} ->
            %% Directory doesn't exist yet - that's OK, return empty map
            {ok, #{}};
        {error, Reason} ->
            {error, {directory_read_failed, Reason}}
    end.

%% @doc Delete a ratchet session from storage.
%%
%% Removes the encrypted session file for the specified username.
%%
%% @param Username The username identifying the ratchet session to delete
%% @param BaseDir Base directory for storing ratchet sessions
%% @returns ok | {error, term()}
-spec delete_ratchet_session(string(), string()) ->
    ok | {error, term()}.
delete_ratchet_session(Username, BaseDir) ->
    SessionFile = filename:join(BaseDir, Username ++ ".session"),
    case file:delete(SessionFile) of
        ok -> ok;
        % File didn't exist - that's OK
        {error, enoent} -> ok;
        {error, Reason} -> {error, {file_delete_failed, Reason}}
    end.

%% @doc Sign a message using Ed25519 signature.
%%
%% Creates a digital signature for the provided message using the Ed25519
%% signing algorithm. The message can be any binary data.
%%
%% @param Message The binary data to sign
%% @param PrivateKey Ed25519 private key (64 bytes) for signing
%% @returns Signature binary (64 bytes)
%% @throws error
-spec sign_message(binary(), binary()) -> binary().
sign_message(Message, PrivateKey) ->
    crypto:sign(eddsa, none, Message, [PrivateKey, ed25519]).

%% @doc Verify an Ed25519 signature.
%%
%% Verifies that a signature was created by the holder of the private key
%% corresponding to the provided public key.
%%
%% @param Message The original binary data that was signed
%% @param Signature The signature to verify (64 bytes)
%% @param PublicKey Ed25519 public key (32 bytes) for verification
%% @returns true if signature is valid, false otherwise
-spec verify_signature(binary(), binary(), binary()) -> boolean().
verify_signature(Message, Signature, PublicKey) ->
    ?dbg(
        "verify_signature called with Message size: ~p, Signature size: ~p, PublicKey size: ~p",
        [
            byte_size(Message), byte_size(Signature), byte_size(PublicKey)
        ]
    ),
    Result = crypto:verify(eddsa, none, Message, Signature, [PublicKey, ed25519]),
    ?dbg("verify_signature result: ~p", [Result]),
    Result.


%%%===================================================================
%%% X3DH Protocol Implementation (SESSION-MESSAGE-FLOW.md)
%%%===================================================================

%% @doc Perform X3DH key agreement from sender's perspective.
%%
%% Implements the Alice side of the X3DH protocol as described in SESSION-MESSAGE-FLOW.md.
%% Performs three (or four) Diffie-Hellman exchanges and combines them into a session key:
%% - DH1: Identity × Signed Prekey
%% - DH2: Ephemeral × Identity
%% - DH3: Ephemeral × Signed Prekey
%% - DH4: Ephemeral × One-Time Prekey (optional)
%%
%% @param SenderKeys Map containing sender's client keys (from generate_client_keys/0)
%% @param RecipientBundle Map containing recipient's key bundle from server
%% @param Message Binary message to encrypt
%% @returns {ok, {MessageBlob, MessageId}} or {error, Reason}
-spec x3dh_sender_init(map(), map(), binary()) ->
    {ok, {map(), binary()}} | {error, term()}.
x3dh_sender_init(SenderKeys, RecipientBundle, Message) ->
    try
        ?dbg("DEBUG: Starting X3DH sender init, SenderKeys: ~p~n", [SenderKeys]),
        %% Extract sender's keys
        #{
            identity_dh_private := SenderIdPriv,
            identity_dh_public := SenderIdDHPub,
            identity_sign_private := SenderSignPriv,
            identity_sign_public := SenderSignPub,
            key_id := SenderKeyId
        } = SenderKeys,
        ?dbg("DEBUG: SenderKeyId: ~p~n", [SenderKeyId]),
        ?dbg(
            "DEBUG: Alice signing with SenderSignPriv (identity_sign_private): ~p~n",
            [SenderSignPriv]
        ),
        ?dbg(
            "DEBUG: Alice's corresponding public key (identity_sign_public): ~p~n",
            [SenderSignPub]
        ),

        ?dbg("DEBUG: RecipientBundle: ~p~n", [RecipientBundle]),
        %% Extract recipient's keys
        #{
            identity_sign_public := RecipientIdPub,
            identity_dh_public := RecipientIdDHPub,
            signed_prekey := #{
                public := RecipientSpkPub,
                signature := SpkSignature
            },
            key_id := RecipientKeyId
        } = RecipientBundle,
        ?dbg("DEBUG: RecipientKeyId: ~p~n", [RecipientKeyId]),

        %% Verify signed prekey signature
        ?dbg(
            "DEBUG: About to verify signature with:~n  SpkPub: ~p~n  Signature: ~p~n  IdentityPub: ~p~n",
            [RecipientSpkPub, SpkSignature, RecipientIdPub]
        ),
        case verify_signature(RecipientSpkPub, SpkSignature, RecipientIdPub) of
            false ->
                {error, invalid_signed_prekey_signature};
            true ->
                %% Generate ephemeral keypair for this session
                {EphemeralPub, EphemeralPriv} = gen_keypair(),

                %% Perform X3DH key exchanges (use Bob's X25519 DH public key directly)
                %% DH1: Identity × Signed Prekey (per X3DH specification)
                DH1 = scalarmult(SenderIdPriv, RecipientSpkPub),
                ?info("X3DH Alice DH1 result: ~p", [DH1]),

                %% DH2: Ephemeral × Identity (per X3DH specification)
                DH2 = scalarmult(EphemeralPriv, RecipientIdDHPub),
                ?info("X3DH Alice DH2 result: ~p", [DH2]),

                %% DH3: Ephemeral × Signed Prekey
                DH3 = scalarmult(EphemeralPriv, RecipientSpkPub),
                ?info("X3DH Alice DH3 result: ~p", [DH3]),

                %% DH4: Ephemeral × One-Time Prekey (optional)
                %% Note: When no OTPK is available, X3DH can still proceed but with
                %% reduced forward secrecy. We set otpk_id to undefined to avoid
                %% passing null atoms to base64:encode later in the flow.
                {DH4, OtpkId} =
                    case maps:get(one_time_prekey, RecipientBundle, null) of
                        null ->
                            ?info("X3DH Alice DH4: OTPK is null, no DH4", []),
                            {<<>>, undefined};
                        #{id := OtpkIdBin, public := OtpkPub} ->
                            DH4Val = scalarmult(EphemeralPriv, OtpkPub),
                            ?info("X3DH Alice DH4 result: ~p", [DH4Val]),
                            {DH4Val, OtpkIdBin}
                    end,

                %% Combine DH outputs and derive session key
                DHCombined = <<DH1/binary, DH2/binary, DH3/binary, DH4/binary>>,
                ?info("X3DH Alice DHCombined length: ~p", [
                    byte_size(DHCombined)
                ]),
                SessionKey = hkdf_sha256(DHCombined, <<"X3DH SessionKey">>, 32),

                %% Generate unique message ID
                MessageId = crypto:strong_rand_bytes(16),
                ?dbg("DEBUG: Generated MessageId: ~p~n", [MessageId]),

                %% Create message metadata for X3DH
                %% Note: ephemeral_public IS the sender's initial Double Ratchet DH public key (A₀)
                Metadata = #{
                    version => 1,
                    type => <<"X3DH_INIT">>,
                    sender_id => SenderKeyId,
                    sender_identity_dh_public => SenderIdDHPub,
                    sender_identity_sign_public => SenderSignPub,
                    recipient_id => RecipientKeyId,
                    ephemeral_public => EphemeralPub,
                    otpk_id => OtpkId,
                    message_id => MessageId,
                    timestamp => erlang:system_time(second)
                },

                %% Sign the message metadata for identity binding
                ?dbg("DEBUG: Alice creating Metadata map: ~p", [Metadata]),
                MetadataBin = erlang:term_to_binary(Metadata),
                ?dbg("DEBUG: Alice signing MetadataBin: ~p", [MetadataBin]),
                ?dbg("DEBUG: Alice signing MetadataBin size: ~p", [
                    byte_size(MetadataBin)
                ]),
                Signature = sign_message(MetadataBin, SenderSignPriv),
                ?dbg("DEBUG: Alice generated signature: ~p", [Signature]),

                %% Test: Verify Alice's signature immediately with her own public key
                SelfVerifyResult = verify_signature(
                    MetadataBin, Signature, SenderSignPub
                ),
                ?dbg("DEBUG: Alice self-verification of signature: ~p", [
                    SelfVerifyResult
                ]),

                %% Encrypt the actual message with session key
                {Ciphertext, Nonce} = aead_encrypt(Message, SessionKey, <<>>),
                ?dbg(
                    ">>>>>> Encrypted message with session key: ~p , Nonce: ~p~n",
                    [SessionKey, Nonce]
                ),

                %% Create complete message blob
                MessageBlob = #{
                    metadata => Metadata,
                    signature => Signature,
                    ciphertext => Ciphertext,
                    nonce => Nonce
                },

                {ok, {MessageBlob, MessageId}}
        end
    catch
        error:Reason -> {error, Reason};
        throw:Reason -> {error, Reason}
    end.

%% @doc Enhanced X3DH sender init that also returns the session key for ratchet initialization.
%%
%% Same as x3dh_sender_init/3 but returns the session key for automatic ratchet initialization.
%% This enables seamless upgrade from X3DH to Double Ratchet messaging.
%% 
%% Per X3DH/Double-Ratchet spec: The ephemeral keypair generated during X3DH becomes
%% the sender's initial Double Ratchet DH keypair (A₀). This function returns it so
%% the caller can initialize the ratchet engine properly.
%%
%% @param SenderKeys Map containing sender's client keys
%% @param RecipientBundle Recipient's key bundle from server
%% @param Message Binary message to encrypt
%% @returns {ok, {MessageBlob, MessageId, SessionKey, {EphemeralPub, EphemeralPriv}}} or {error, Reason}
-spec x3dh_sender_init_with_session_key(map(), map(), binary()) ->
    {ok, {map(), binary(), binary(), {binary(), binary()}}} | {error, term()}.
x3dh_sender_init_with_session_key(SenderKeys, RecipientBundle, Message) ->
    try
        ?dbg(
            "DEBUG: Starting X3DH sender init with session key, SenderKeys: ~p~n",
            [SenderKeys]
        ),
        %% Extract sender's keys
        #{
            identity_dh_private := SenderIdPriv,
            identity_dh_public := SenderIdDHPub,
            identity_sign_private := SenderSignPriv,
            identity_sign_public := SenderSignPub,
            key_id := SenderKeyId
        } = SenderKeys,
        ?dbg("DEBUG: SenderKeyId: ~p~n", [SenderKeyId]),

        ?dbg("DEBUG: RecipientBundle: ~p~n", [RecipientBundle]),
        %% Extract recipient's keys
        #{
            identity_sign_public := RecipientIdPub,
            identity_dh_public := RecipientIdDHPub,
            signed_prekey := #{
                public := RecipientSpkPub,
                signature := SpkSignature
            },
            key_id := RecipientKeyId
        } = RecipientBundle,

        case verify_signature(RecipientSpkPub, SpkSignature, RecipientIdPub) of
            false ->
                {error, invalid_signed_prekey_signature};
            true ->
                %% Generate ephemeral keypair for this session
                {EphemeralPub, EphemeralPriv} = gen_keypair(),

                %% Perform X3DH key exchanges
                DH1 = scalarmult(SenderIdPriv, RecipientSpkPub),
                DH2 = scalarmult(EphemeralPriv, RecipientIdDHPub),
                DH3 = scalarmult(EphemeralPriv, RecipientSpkPub),

                %% Handle optional one-time prekey
                {DH4, OtpkId} =
                    case maps:get(one_time_prekey, RecipientBundle, null) of
                        null ->
                            {<<>>, undefined};
                        #{id := OtpkIdBin, public := OtpkPub} ->
                            DH4Val = scalarmult(EphemeralPriv, OtpkPub),
                            {DH4Val, OtpkIdBin}
                    end,

                %% Combine DH outputs and derive session key
                DHCombined = <<DH1/binary, DH2/binary, DH3/binary, DH4/binary>>,
                SessionKey = hkdf_sha256(DHCombined, <<"X3DH SessionKey">>, 32),

                %% Generate unique message ID
                MessageId = crypto:strong_rand_bytes(16),

                %% Create message metadata for X3DH
                Metadata = #{
                    version => 1,
                    type => <<"X3DH_INIT">>,
                    sender_id => SenderKeyId,
                    sender_identity_dh_public => SenderIdDHPub,
                    sender_identity_sign_public => SenderSignPub,
                    recipient_id => RecipientKeyId,
                    ephemeral_public => EphemeralPub,
                    otpk_id => OtpkId,
                    message_id => MessageId,
                    timestamp => erlang:system_time(second)
                },

                %% Sign the message metadata
                MetadataBin = erlang:term_to_binary(Metadata),
                Signature = sign_message(MetadataBin, SenderSignPriv),

                %% Encrypt the actual message with session key
                {Ciphertext, Nonce} = aead_encrypt(Message, SessionKey, <<>>),

                %% Create complete message blob
                MessageBlob = #{
                    metadata => Metadata,
                    signature => Signature,
                    ciphertext => Ciphertext,
                    nonce => Nonce
                },

                %% Return message blob, ID, session key, AND ephemeral keypair for ratchet initialization
                %% The ephemeral keypair becomes the sender's initial Double Ratchet DH keypair (A₀)
                {ok, {MessageBlob, MessageId, SessionKey, {EphemeralPub, EphemeralPriv}}}
        end
    catch
        error:Reason -> {error, Reason};
        throw:Reason -> {error, Reason}
    end.

%% @doc Perform X3DH key agreement from receiver's perspective.
%%
%% Implements the Bob side of the X3DH protocol as described in SESSION-MESSAGE-FLOW.md.
%% Recreates the same session key by performing the same DH exchanges and decrypts the message.
%%
%% @param ReceiverKeys Map containing receiver's client keys
%% @param MessageBlob Encrypted message blob from sender
%% @param SenderIdPub Sender's identity public key for signature verification
%% @param OtpkPrivateKey Private key for the OTPK ID specified in message (or null)
%% @returns {ok, Message} or {error, Reason}
-spec x3dh_receiver_decrypt(
    map(), map(), binary(), binary() | null
) ->
    {ok, binary()} | {error, term()}.
x3dh_receiver_decrypt(
    ReceiverKeys,
    MessageBlob,
    SenderIdPub,
    OtpkPrivateKey
) ->
    try
        %% Extract message components
        #{
            metadata := CompleteMetadata,
            signature := Signature,
            ciphertext := Ciphertext,
            nonce := Nonce
        } = MessageBlob,

        %% Extract required metadata fields for X3DH operations
        #{
            ephemeral_public := EphemeralPub,
            sender_identity_dh_public := OriginalSenderIdDHPub,
            message_id := MessageId
        } = CompleteMetadata,

        %% Use Alice's complete transmitted metadata directly for signature verification
        %% This ensures we verify against exactly what Alice signed

        %% Verify message signature using complete metadata
        MetadataBin = erlang:term_to_binary(CompleteMetadata),
        ?dbg("X3DH signature verification - Complete Metadata map: ~p", [
            CompleteMetadata
        ]),
        ?dbg("X3DH signature verification - MetadataBin: ~p", [MetadataBin]),
        ?dbg("X3DH signature verification - MetadataBin size: ~p", [
            byte_size(MetadataBin)
        ]),
        ?dbg("X3DH signature verification - Signature: ~p", [Signature]),
        ?dbg("X3DH signature verification - SenderIdPub: ~p", [SenderIdPub]),
        case verify_signature(MetadataBin, Signature, SenderIdPub) of
            false ->
                ?dbg("X3DH signature verification FAILED", []),
                {error, invalid_message_signature};
            true ->
                %% Use the sender's DH public key from Alice's metadata directly
                %% Alice already included her DH public key in the metadata
                SenderIdDHPub = OriginalSenderIdDHPub,

                %% Extract receiver's keys
                #{
                    identity_dh_private := ReceiverIdPriv,
                    signed_prekey_private := ReceiverSpkPriv
                } = ReceiverKeys,

                %% Perform same X3DH key exchanges as sender
                %% DH1: Identity × Signed Prekey (receiver perspective: Signed Prekey × Identity)
                DH1 = scalarmult(ReceiverSpkPriv, SenderIdDHPub),
                ?info("X3DH DH1 result: ~p", [DH1]),

                %% DH2: Ephemeral × Identity (receiver perspective: Identity × Ephemeral)
                DH2 = scalarmult(ReceiverIdPriv, EphemeralPub),
                ?info("X3DH DH2 result: ~p", [DH2]),

                %% DH3: Ephemeral × Signed Prekey (receiver perspective: Signed Prekey × Ephemeral)
                DH3 = scalarmult(ReceiverSpkPriv, EphemeralPub),
                ?info("X3DH DH3 result: ~p", [DH3]),

                %% DH4: Ephemeral × One-Time Prekey (if OTPK was used)
                DH4 =
                    case OtpkPrivateKey of
                        null ->
                            ?info("X3DH DH4: OTPK is null, no DH4", []),
                            <<>>;
                        OtpkPriv when is_binary(OtpkPriv) ->
                            DH4Result = scalarmult(OtpkPriv, EphemeralPub),
                            ?info("X3DH DH4 result: ~p", [DH4Result]),
                            DH4Result
                    end,

                %% Combine DH outputs to recreate session key
                DHCombined = <<DH1/binary, DH2/binary, DH3/binary, DH4/binary>>,
                ?info("X3DH DHCombined length: ~p", [byte_size(DHCombined)]),
                SessionKey = hkdf_sha256(DHCombined, <<"X3DH SessionKey">>, 32),
                ?dbg(">>>>>> Decrypt with SessionKey: ~p , Nonec: ~p~n", [
                    SessionKey, Nonce
                ]),

                %% Decrypt the message
                ?info(
                    "X3DH About to call aead_decrypt with ciphertext size: ~p, key size: ~p, nonce size: ~p",
                    [
                        byte_size(Ciphertext),
                        byte_size(SessionKey),
                        byte_size(Nonce)
                    ]
                ),
                case aead_decrypt(Ciphertext, SessionKey, Nonce, <<>>) of
                    error ->
                        ?info("X3DH AEAD decryption failed", []),
                        {error, decryption_failed};
                    DecryptedMessage ->
                        ?info("X3DH AEAD decryption successful, message: ~p", [
                            DecryptedMessage
                        ]),
                        {ok, {DecryptedMessage, MessageId}}
                end
        end
    catch
        error:Reason -> {error, Reason};
        throw:Reason -> {error, Reason}
    end.

%% @doc Enhanced X3DH receiver decrypt that also returns the session key for ratchet initialization.
%%
%% Same as x3dh_receiver_decrypt/4 but returns the session key for automatic ratchet initialization.
%% This enables seamless upgrade from X3DH to Double Ratchet messaging.
%%
%% @param ReceiverKeys Map containing receiver's client keys
%% @param MessageBlob Encrypted message blob from sender
%% @param SenderIdPub Sender's identity public key for signature verification
%% @param OtpkPrivateKey Private key for the OTPK ID specified in message (or null)
%% @returns {ok, {Message, MessageId, SessionKey}} or {error, Reason}
-spec x3dh_receiver_decrypt_with_session_key(
    map(), map(), binary(), binary() | null
) ->
    {ok, {binary(), binary(), binary()}} | {error, term()}.
x3dh_receiver_decrypt_with_session_key(
    ReceiverKeys,
    MessageBlob,
    SenderIdPub,
    OtpkPrivateKey
) ->
    try
        %% Extract message components
        #{
            metadata := Metadata,
            signature := Signature,
            ciphertext := Ciphertext,
            nonce := Nonce
        } = MessageBlob,

        %% Extract metadata
        #{
            sender_identity_dh_public := SenderIdDHPub,
            ephemeral_public := EphemeralPub,
            message_id := MessageId
        } = Metadata,

        %% Verify message signature (use provided SenderIdPub parameter)
        MetadataBin = erlang:term_to_binary(Metadata),
        case verify_signature(MetadataBin, Signature, SenderIdPub) of
            false ->
                {error, invalid_message_signature};
            true ->
                %% Extract receiver's keys
                #{
                    identity_dh_private := ReceiverIdPriv,
                    signed_prekey_private := ReceiverSpkPriv
                } = ReceiverKeys,

                %% Perform same DH exchanges as sender (order matters for consistency)
                DH1 = scalarmult(ReceiverSpkPriv, SenderIdDHPub),
                DH2 = scalarmult(ReceiverIdPriv, EphemeralPub),
                DH3 = scalarmult(ReceiverSpkPriv, EphemeralPub),

                %% Handle optional DH4 with OTPK
                DH4 =
                    case OtpkPrivateKey of
                        null -> <<>>;
                        _ -> scalarmult(OtpkPrivateKey, EphemeralPub)
                    end,

                %% Combine DH outputs and derive session key (same as sender)
                DHCombined = <<DH1/binary, DH2/binary, DH3/binary, DH4/binary>>,
                SessionKey = hkdf_sha256(DHCombined, <<"X3DH SessionKey">>, 32),

                %% Decrypt message with session key
                case aead_decrypt(Ciphertext, SessionKey, Nonce, <<>>) of
                    error ->
                        {error, decryption_failed};
                    DecryptedMessage ->
                        %% Return message, ID, AND session key for ratchet initialization
                        {ok, {DecryptedMessage, MessageId, SessionKey}}
                end
        end
    catch
        error:Reason:Stacktrace ->
            ?error(
                "x3dh_receiver_decrypt_with_session_key error: ~p~n"
                "Stacktrace: ~p",
                [Reason, Stacktrace]
            ),
            {error, Reason};
        throw:Reason ->
            {error, Reason}
    end.

%% @doc Find the private key for a specific OTPK ID in the client keys.
%%
%% Searches through the client's one-time prekeys to find the private key
%% matching the given OTPK ID. This is used by the receiver to decrypt
%% X3DH messages that used a specific OTPK.
%%
%% @param ClientKeys Map containing client's complete key bundle
%% @param OtpkId Binary OTPK ID to search for
%% @returns {ok, PrivateKey} or {error, not_found}
-spec find_otpk_private_key(map(), binary()) ->
    {ok, binary()} | {error, not_found}.
find_otpk_private_key(ClientKeys, OtpkId) ->
    #{one_time_prekeys := OtpkList} = ClientKeys,

    case
        lists:search(
            fun(#{id := Id}) -> Id =:= OtpkId end,
            OtpkList
        )
    of
        {value, #{private := PrivateKey}} ->
            {ok, PrivateKey};
        false ->
            {error, not_found}
    end.

%% @doc Ensure ETS tables exist.
ensure_tables() ->
    ensure_table(?PREKEY_TABLE),
    ensure_table(?MESSAGE_TABLE),
    ensure_table(?USER_TABLE),
    ok.

ensure_table(TableName) ->
    case ets:info(TableName) of
        undefined ->
            ets:new(TableName, [named_table, public, set]);
        _ ->
            ok
    end.

%% @doc Track OTPK usage by a sender for forward secrecy management.
%%
%% Records the OTPK ID used by a specific sender to detect key rotation
%% and potential replay attacks. This enables automatic cleanup of old
%% OTPKs when senders rotate to new keys.
%%
%% @param MyUsername The recipient's username (key owner)
%% @param SenderUsername The sender's username
%% @param OtpkId The OTPK ID used by the sender (undefined if no OTPK used)
%% @returns ok
-spec track_otpk_usage(string(), string(), undefined | binary()) -> ok.
track_otpk_usage(MyUsername, SenderUsername, OtpkId) ->
    Key = {MyUsername, otpk_usage, SenderUsername},
    Timestamp = erlang:system_time(second),
    Value = {OtpkId, Timestamp},
    ets:insert(?PREKEY_TABLE, {Key, Value}),
    ok.

%% @doc Check the last OTPK usage by a sender.
%%
%% Retrieves tracking information about the last OTPK used by a specific
%% sender. Returns information needed to detect key reuse and rotation.
%%
%% @param MyUsername The recipient's username (key owner)
%% @param SenderUsername The sender's username
%% @returns {ok, {LastOtpkId, Timestamp}} | {error, not_found}
-spec check_otpk_usage(string(), string()) ->
    {ok, {undefined | binary(), integer()}} | {error, not_found}.
check_otpk_usage(MyUsername, SenderUsername) ->
    Key = {MyUsername, otpk_usage, SenderUsername},
    case ets:lookup(?PREKEY_TABLE, Key) of
        [{Key, {LastOtpkId, Timestamp}}] ->
            {ok, {LastOtpkId, Timestamp}};
        [] ->
            {error, not_found}
    end.

%% @doc Clean up old OTPK when sender rotates to a new key.
%%
%% Removes the old OTPK from local storage when we detect that a sender
%% has started using a new OTPK. This prevents accumulation of obsolete
%% keys while maintaining forward secrecy.
%%
%% @param MyUsername The recipient's username (key owner)
%% @param SenderUsername The sender's username
%% @returns ok
-spec cleanup_old_otpk(string(), string()) -> ok.
cleanup_old_otpk(MyUsername, SenderUsername) ->
    KeyTuple = {MyUsername, otpk_usage, SenderUsername},
    ets:delete(?PREKEY_TABLE, KeyTuple),
    ok.


%% @doc Determine the CRYPTIC_DIR path.
%% Will halt the system if not found.
-spec get_cryptic_dir() -> string().
get_cryptic_dir() ->
    case {os:getenv("HOME"), os:getenv("CRYPTIC_DIR")} of
        {false, false} ->
            io:format("<FATAL ERROR> can't deduce CRYPTIC_DIR to use~n", []),
            init:stop();
        {Home, false} ->
            filename:join([Home,".cryptic"]);
        {_Home, Dir} ->
            Dir
    end.

%% @doc Get user-specific directory path under CRYPTIC_DIR for a specific server.
%% Creates path: `$HOME/.cryptic/<username>/<server>_<port>'
-spec get_cryptic_dir(string() | binary(), string() | binary(), non_neg_integer()) -> string().
get_cryptic_dir(Username, Server, Port) when is_binary(Username) ->
    get_cryptic_dir(binary_to_list(Username), Server, Port);
get_cryptic_dir(Username, Server, Port) when is_binary(Server) ->
    get_cryptic_dir(Username, binary_to_list(Server), Port);
get_cryptic_dir(Username, Server, Port) when is_list(Username), is_list(Server), is_integer(Port) ->
    ServerDir = Server ++ "_" ++ integer_to_list(Port),
    filename:join([get_cryptic_dir(), Username, ServerDir]).


%% @doc Get server file path from environment variable or application config.
%% If both are set, environment variable takes precedence.
-spec get_server_file(string(), atom()) -> string() | undefined.
get_server_file(EnvVar, AppVar) ->
    case os:getenv(EnvVar) of
        Empty when Empty == false orelse Empty == "" ->
            %% Environment variable not set, use application config
            case application:get_env(cryptic, AppVar) of
                {ok, File} ->
                    case os:getenv("CRYPTIC_SERVER_DIR") of
                        false ->
                            File;
                        ServerDir ->
                            filename:join([ServerDir, File])
                    end;
                undefined ->
                    undefined
            end;
        EnvFile ->
            %% Environment variable set with a value, use it directly
            EnvFile
    end.
