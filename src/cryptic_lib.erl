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
%%%   <li>Private keys are stored encrypted with AES-256-GCM using PBKDF2-derived keys</li>
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
%%% == Key Management ==
%%%
%%% <ul>
%%%   <li>**Key Generation**: Deterministic Ed25519/X25519 key derivation from master seed</li>
%%%   <li>**Key Storage**: AES-256-GCM encryption with PBKDF2-derived passphrase keys</li>
%%%   <li>**One-Time Prekeys**: X25519 keypairs with unique IDs for single-use consumption</li>
%%%   <li>**libsodium Integration**: Secure curve conversion utilities via NIF interface</li>
%%% </ul>
%%%
%%% == Example Usage ==
%%%
%%% ```
%%% %% Initialize client with X3DH key bundle
%%% Keys = cryptic_lib:generate_client_keys(),
%%% #{identity_sign_public := IdentitySignPub,
%%%   identity_dh_public := IdentityDHPub,
%%%   signed_prekey_public := SignedPrekeyPub,
%%%   one_time_prekeys := OneTimePrekeys} = Keys,
%%%
%%% %% Encrypt and save keys to file
%%% Passphrase = <<"secure_passphrase">>,
%%% ok = cryptic_lib:save_encrypted_keys(Keys, Passphrase, "/path/to/keys.encrypted"),
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
%%% {Ciphertext, Nonce} = cryptic_lib:aead_encrypt(<<"Hello">>, AeadKey, <<>>),
%%%
%%% %% Decrypt message
%%% Plaintext = cryptic_lib:aead_decrypt(Ciphertext, AeadKey, Nonce, <<>>).
%%% '''
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
    store_message/2,
    get_messages/1,
    %% Key management functions
    generate_client_keys/0,
    generate_one_time_prekeys/1,
    ed25519_to_x25519_private/1,
    ed25519_to_x25519_public/1,
    derive_key_from_passphrase/2,
    encrypt_keys/2,
    decrypt_keys/2,
    save_encrypted_keys/3,
    load_encrypted_keys/2,
    initialize_client_keys/2,
    %% Message signing functions
    sign_message/2,
    verify_signature/3,
    %% Secure message functions with metadata
    encrypt_message_secure/3,
    decrypt_message_secure/3,
    %% Sequence number management
    get_next_sequence/2,
    validate_sequence/3,
    update_sequence/3,
    %% Key bundle management
    store_key_bundle/2,
    get_key_bundle/1,
    get_signed_prekey_with_signature/1,
    mark_otpk_consumed/2,
    get_available_otpks/1,
    get_key_status/1,
    %% Identity keys management
    store_identity_keys/2,
    store_prekey_bundle/2,
    %% X3DH Protocol Implementation
    x3dh_sender_init/3,
    x3dh_receiver_decrypt/4,
    find_otpk_private_key/2
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
%% ```
%% {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
%% io:format("Public key: ~p~n", [base64:encode(PubKey)]).
%% '''
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
%% ```
%% %% Alice and Bob generate keypairs
%% {AlicePub, AlicePriv} = cryptic_lib:gen_keypair(),
%% {BobPub, BobPriv} = cryptic_lib:gen_keypair(),
%%
%% %% Both can compute the same shared secret
%% SharedSecret1 = cryptic_lib:scalarmult(AlicePriv, BobPub),
%% SharedSecret2 = cryptic_lib:scalarmult(BobPriv, AlicePub),
%% true = SharedSecret1 =:= SharedSecret2.
%% '''
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
%% ```
%% Key = cryptic_lib:rand_bytes(32),
%% Message = <<"Hello, World!">>,
%% AAD = <<"metadata">>,
%% {Ciphertext, Nonce} = cryptic_lib:aead_encrypt(Message, Key, AAD).
%% '''
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
%% ```
%% Key = cryptic_lib:rand_bytes(32),
%% {Ciphertext, Nonce} = cryptic_lib:aead_encrypt(<<"Secret">>, Key, <<>>),
%% Plaintext = cryptic_lib:aead_decrypt(Ciphertext, Key, Nonce, <<>>).
%% '''
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
%% ```
%% %% Generate a 256-bit encryption key
%% Key = cryptic_lib:rand_bytes(32),
%%
%% %% Generate a random salt for key derivation
%% Salt = cryptic_lib:rand_bytes(16).
%% '''
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
%% ```
%% SharedSecret = cryptic_lib:scalarmult(PrivKey, PubKey),
%% EncKey = cryptic_lib:hkdf_sha256(SharedSecret, <<"encryption">>, 32),
%% MacKey = cryptic_lib:hkdf_sha256(SharedSecret, <<"authentication">>, 32).
%% '''
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
%% ```
%% SharedSecret = cryptic_lib:scalarmult(PrivKey, PubKey),
%% Salt = cryptic_lib:rand_bytes(32),
%% EncKey = cryptic_lib:hkdf_sha256(SharedSecret, Salt, <<"encryption">>, 32).
%% '''
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
%% ```
%% SharedSecret = cryptic_lib:scalarmult(MyPrivKey, TheirPubKey),
%% {AeadKey, Salt} = cryptic_lib:derive_aead_key_random(SharedSecret),
%% %% Salt must be transmitted with the message for decryption
%% '''
%%
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
%% ```
%% {EphemeralPub, EphemeralPriv} = cryptic_lib:gen_keypair(),
%% SharedSecret = cryptic_lib:scalarmult(EphemeralPriv, RecipientPubKey),
%% AeadKey = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, EphemeralPub).
%% '''
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
%% ```
%% SharedSecret = cryptic_lib:scalarmult(MyPrivKey, TheirPubKey),
%% AeadKey = cryptic_lib:derive_aead_key_simple(SharedSecret).
%% '''
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
%%   - {SenderID, RecipientID} -> Sequence numbers
-define(PREKEY_TABLE, cryptic_prekeys).
-define(MESSAGE_TABLE, cryptic_messages).
-define(USER_TABLE, cryptic_users).
-define(SEQUENCE_TABLE, cryptic_sequences).

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

%% @doc Store a message for a user.
-spec store_message(string(), map()) -> ok.
store_message(ToUser, MessageBlob) ->
    MessageId = erlang:unique_integer([positive]),
    ets:insert(?MESSAGE_TABLE, {MessageId, ToUser, MessageBlob}),
    ok.

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
    KeysFile = filename:join(ConfigDir, "keys.encrypted"),

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

%% @doc Derive encryption key from passphrase using PBKDF2.
-spec derive_key_from_passphrase(string() | binary(), binary()) -> binary().
derive_key_from_passphrase(Passphrase, Salt) when is_list(Passphrase) ->
    derive_key_from_passphrase(list_to_binary(Passphrase), Salt);
derive_key_from_passphrase(Passphrase, Salt) when is_binary(Passphrase) ->
    % PBKDF2 iterations
    Iterations = 100000,
    % 256-bit key
    KeyLength = 32,
    crypto:pbkdf2_hmac(sha256, Passphrase, Salt, Iterations, KeyLength).

%% @doc Encrypt private key material with passphrase-derived key.
-spec encrypt_keys(#{}, string() | binary()) -> {binary(), binary()}.
encrypt_keys(Keys, Passphrase) when is_list(Passphrase) ->
    encrypt_keys(Keys, list_to_binary(Passphrase));
encrypt_keys(Keys, Passphrase) when is_binary(Passphrase) ->
    %% Generate random salt
    Salt = crypto:strong_rand_bytes(16),

    %% Derive encryption key
    EncKey = derive_key_from_passphrase(Passphrase, Salt),

    %% Serialize keys to binary
    KeysBinary = term_to_binary(Keys),

    %% Encrypt with AES-256-GCM
    IV = crypto:strong_rand_bytes(12),
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(
        aes_256_gcm, EncKey, IV, KeysBinary, <<>>, true
    ),

    %% Combine all encrypted data
    EncryptedData =
        <<Salt:16/binary, IV:12/binary, Tag:16/binary, Ciphertext/binary>>,

    {EncryptedData, Salt}.

%% @doc Decrypt private key material with passphrase-derived key.
-spec decrypt_keys(binary(), string() | binary()) ->
    {ok, #{}} | {error, term()}.
decrypt_keys(EncryptedData, Passphrase) when is_list(Passphrase) ->
    decrypt_keys(EncryptedData, list_to_binary(Passphrase));
decrypt_keys(EncryptedData, Passphrase) when is_binary(Passphrase) ->
    try
        %% Extract components
        <<Salt:16/binary, IV:12/binary, Tag:16/binary, Ciphertext/binary>> =
            EncryptedData,

        %% Derive decryption key
        DecKey = derive_key_from_passphrase(Passphrase, Salt),

        %% Decrypt with AES-256-GCM
        case
            crypto:crypto_one_time_aead(
                aes_256_gcm, DecKey, IV, Ciphertext, <<>>, Tag, false
            )
        of
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

%% @doc Save encrypted keys to file.
-spec save_encrypted_keys(#{}, string() | binary(), string()) ->
    ok | {error, term()}.
save_encrypted_keys(Keys, Passphrase, KeysFile) ->
    %% Encrypt keys
    {EncryptedData, _Salt} = encrypt_keys(Keys, Passphrase),

    %% Write to file
    case file:write_file(KeysFile, EncryptedData) of
        ok ->
            % rw-------
            file:change_mode(KeysFile, 8#600),
            ok;
        {error, Reason} ->
            {error, {file_write_error, Reason}}
    end.

%% @doc Load and decrypt keys from file.
-spec load_encrypted_keys(string(), string() | binary()) ->
    {ok, #{}} | {error, term()}.
load_encrypted_keys(KeysFile, Passphrase) ->
    case file:read_file(KeysFile) of
        {ok, EncryptedData} ->
            decrypt_keys(EncryptedData, Passphrase);
        {error, Reason} ->
            {error, {file_read_error, Reason}}
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

%% @doc Encrypt message with metadata using sign-then-encrypt approach.
%%
%% Implements Step 1 of the Architecture Sketch: proper message integrity
%% with metadata inclusion and sign-then-encrypt ordering.
%%
%% The function:
%% <ol>
%%   <li>Creates a message envelope with metadata (sender, recipient, timestamp, sequence)</li>
%%   <li>Signs the envelope with the sender's Ed25519 identity key</li>
%%   <li>Encrypts the signed envelope using X25519 ECDH with recipient's key</li>
%% </ol>
%%
%% @param Message The plaintext message to send
%% @param Metadata Map containing:
%%   - sender_id: Sender user ID (binary)
%%   - recipient_id: Recipient user ID (binary)
%%   - sender_key_id: Sender's key identifier (binary)
%%   - timestamp: Unix timestamp (integer)
%%   - sequence: Message sequence number (integer)
%%   - sender_sign_key: Sender's Ed25519 private key (binary)
%% @param RecipientPubKey Recipient's X25519 public key (32 bytes)
%% @returns {ok, {EphemeralPubKey, Nonce, Ciphertext}} or {error, Reason}
-spec encrypt_message_secure(binary(), map(), binary()) ->
    {ok, {binary(), binary(), binary()}} | {error, term()}.
encrypt_message_secure(Message, Metadata, RecipientPubKey) ->
    try
        #{
            sender_id := SenderID,
            recipient_id := RecipientID,
            sender_key_id := SenderKeyID,
            timestamp := Timestamp,
            sequence := Sequence,
            sender_sign_key := SenderSignKey
        } = Metadata,

        %% Create message envelope with metadata
        Envelope = #{
            message => Message,
            sender_id => SenderID,
            recipient_id => RecipientID,
            sender_key_id => SenderKeyID,
            timestamp => Timestamp,
            sequence => Sequence
        },

        %% Serialize envelope for signing
        EnvelopeBin = erlang:term_to_binary(Envelope),

        %% Sign the envelope (sign-then-encrypt)
        Signature = sign_message(EnvelopeBin, SenderSignKey),

        %% Create signed message package
        SignedPackage = #{
            envelope => Envelope,
            signature => Signature
        },
        SignedPackageBin = erlang:term_to_binary(SignedPackage),

        %% Generate ephemeral keypair for encryption
        {EphPub, EphPriv} = gen_keypair(),

        %% Compute shared secret and encrypt
        Shared = scalarmult(EphPriv, RecipientPubKey),
        AeadKey = derive_aead_key_ephemeral(Shared, EphPub),
        {Cipher, Nonce} = aead_encrypt(SignedPackageBin, AeadKey, <<>>),

        {ok, {EphPub, Nonce, Cipher}}
    catch
        error:Reason -> {error, Reason}
    end.

%% @doc Decrypt message and verify metadata using encrypt-then-verify approach.
%%
%% Implements Step 1 of the Architecture Sketch: proper message integrity
%% verification with metadata validation.
%%
%% The function:
%% <ol>
%%   <li>Decrypts the message using X25519 ECDH with recipient's private key</li>
%%   <li>Extracts the signed envelope and signature</li>
%%   <li>Verifies the signature using sender's Ed25519 public key</li>
%%   <li>Validates metadata (timestamp freshness, sequence numbers, etc.)</li>
%% </ol>
%%
%% @param EncryptedBlob Tuple {EphemeralPubKey, Nonce, Ciphertext}
%% @param RecipientPrivKey Recipient's X25519 private key (32 bytes)
%% @param SenderPubKey Sender's Ed25519 public key for signature verification (32 bytes)
%% @returns {ok, {Message, Metadata}} or {error, Reason}
-spec decrypt_message_secure(
    {binary(), binary(), binary()}, binary(), binary()
) ->
    {ok, {binary(), map()}} | {error, term()}.
decrypt_message_secure(
    {Ephemeral, Nonce, Cipher}, RecipientPrivKey, SenderPubKey
) ->
    try
        %% Decrypt the message
        Shared = scalarmult(RecipientPrivKey, Ephemeral),
        AeadKey = derive_aead_key_ephemeral(Shared, Ephemeral),

        case aead_decrypt(Cipher, AeadKey, Nonce, <<>>) of
            error ->
                {error, decryption_failed};
            SignedPackageBin ->
                %% Deserialize signed package
                SignedPackage = erlang:binary_to_term(SignedPackageBin),
                #{envelope := Envelope, signature := Signature} = SignedPackage,

                %% Serialize envelope for signature verification
                EnvelopeBin = erlang:term_to_binary(Envelope),

                %% Verify signature
                case verify_signature(EnvelopeBin, Signature, SenderPubKey) of
                    false ->
                        {error, signature_verification_failed};
                    true ->
                        %% Extract message and metadata
                        #{message := Message} = Envelope,
                        {ok, {Message, Envelope}}
                end
        end
    catch
        error:Reason -> {error, Reason}
    end.

%% @doc Store complete key bundle for a user with signatures and metadata.
%%
%% Stores the complete key bundle using PREKEY_TABLE structured format:
%% - {Username, identity} -> Identity keys and signed prekey with signature
%% - {Username, otpk, KeyId} -> Individual one-time prekeys
%%
%% @param Username User ID
%% @param KeyBundle Complete key bundle map from generate_client_keys/0
%% @returns ok
-spec store_key_bundle(string(), map()) -> ok.
store_key_bundle(Username, KeyBundle) ->
    ?dbg("Storing key bundle for username: ~p", [Username]),
    #{
        identity_sign_public := IdentitySignPub,
        signed_prekey_public := SignedPrekeyPub,
        signed_prekey_signature := SignedPrekeySignature,
        one_time_prekeys := OneTimePrekeys,
        key_id := KeyId
    } = KeyBundle,

    ?dbg("store_key_bundle: IdentitySignPub: ~p", [IdentitySignPub]),
    ?dbg("store_key_bundle: SignedPrekeyPub: ~p", [SignedPrekeyPub]),
    ?dbg("store_key_bundle: SignedPrekeySignature: ~p", [
        SignedPrekeySignature
    ]),

    %% Store identity data in PREKEY_TABLE format
    IdentityData = #{
        username => Username,
        key_id => KeyId,
        identity_public => IdentitySignPub,
        signed_prekey => #{
            public => SignedPrekeyPub,
            signature => SignedPrekeySignature,
            timestamp => erlang:system_time(second)
        },
        created_at => erlang:system_time(second)
    },

    ?dbg("Storing identity and ~p OTPKs for ~p", [
        length(OneTimePrekeys), Username
    ]),
    ets:insert(?PREKEY_TABLE, {{Username, identity}, IdentityData}),

    %% Store each one-time prekey individually
    lists:foreach(
        fun(#{id := OtpkId, public := OtpkPub}) ->
            KeyTuple = {Username, otpk, OtpkId},
            PrekeyData = #{
                username => Username,
                key_id => OtpkId,
                public_key => OtpkPub,
                consumed => false,
                created_at => erlang:system_time(second)
            },
            ets:insert(?PREKEY_TABLE, {KeyTuple, PrekeyData})
        end,
        OneTimePrekeys
    ),

    %% Update user record
    ets:insert(?USER_TABLE, {Username, erlang:system_time(second)}),
    ?dbg("Successfully stored key bundle for ~p", [Username]),
    ok.

%% @doc Store identity keys for a user (5-step authentication flow).
%%
%% Stores the user's identity keys including the public identity key,
%% signed prekey, and prekey signature. This is used in the new
%% 5-step authentication flow where identity keys are uploaded separately
%% from one-time prekey bundles.
%%
%% @param Username User ID
%% @param IdentityKeys Map containing identity key components
%% @returns ok or {error, Reason}
-spec store_identity_keys(string(), map()) -> ok | {error, term()}.
store_identity_keys(Username, IdentityKeys) ->
    try
        #{
            identity_sign_public := IdentitySignPub,
            identity_dh_public := IdentityDHPub,
            signed_prekey_public := SignedPrekeyPub,
            signed_prekey_signature := Signature,
            timestamp := Timestamp
        } = IdentityKeys,

        %% Store identity keys with structured tuple key
        IdentityData = #{
            username => Username,
            identity_sign_public => IdentitySignPub,
            identity_dh_public => IdentityDHPub,
            signed_prekey => #{
                public => SignedPrekeyPub,
                signature => Signature,
                timestamp => Timestamp
            },
            created_at => erlang:system_time(second)
        },

        %% Use structured tuple key: {username, identity}
        ets:insert(?PREKEY_TABLE, {{Username, identity}, IdentityData}),
        ets:insert(?USER_TABLE, {Username, erlang:system_time(second)}),
        ok
    catch
        error:{badkey, Key} ->
            {error, {missing_key, Key}};
        _:Error ->
            {error, Error}
    end.

%% @doc Store prekey bundle (one-time prekeys) for a user.
%%
%% Stores a list of one-time prekeys for forward secrecy. This is used
%% in step 5 of the new authentication flow where prekey bundles are
%% uploaded separately from identity keys.
%%
%% @param Username User ID
%% @param PrekeyList List of prekey maps with id and public key
%% @returns ok or {error, Reason}
-spec store_prekey_bundle(string(), [map()]) -> ok | {error, term()}.
store_prekey_bundle(Username, PrekeyList) ->
    try
        %% Store each one-time prekey individually with structured tuple keys
        lists:foreach(
            fun(#{id := KeyId, public := PubKey}) ->
                %% Use structured tuple key: {username, otpk, key_id}
                KeyTuple = {Username, otpk, KeyId},
                PrekeyData = #{
                    username => Username,
                    key_id => KeyId,
                    public_key => PubKey,
                    consumed => false,
                    created_at => erlang:system_time(second)
                },
                ets:insert(?PREKEY_TABLE, {KeyTuple, PrekeyData})
            end,
            PrekeyList
        ),

        %% Update user record
        ets:insert(?USER_TABLE, {Username, erlang:system_time(second)}),
        ok
    catch
        _:Error ->
            {error, Error}
    end.

%% @doc Get complete key bundle for a user with fresh OTPK list.
%%
%% Retrieves the user's complete key bundle from PREKEY_TABLE structured format.
%% Reconstructs the bundle from identity data and available OTPKs.
%%
%% @param Username User ID
%% @returns {ok, KeyBundle} or {error, not_found}
-spec get_key_bundle(string()) -> {ok, map()} | {error, not_found}.
get_key_bundle(Username) ->
    ?dbg("Looking up key bundle for username: ~p", [Username]),

    %% Look for identity entry in PREKEY_TABLE
    case ets:lookup(?PREKEY_TABLE, {Username, identity}) of
        [{{Username, identity}, IdentityData}] ->
            ?dbg("Found identity data for ~p", [Username]),
            %% Extract identity data
            #{
                identity_sign_public := IdentitySignPub,
                identity_dh_public := IdentityDHPub,
                signed_prekey := #{
                    public := SignedPrekeyPub,
                    signature := SignedPrekeySignature,
                    timestamp := Timestamp
                }
            } = IdentityData,

            ?dbg("get_key_bundle: Retrieved IdentitySignPub: ~p", [
                IdentitySignPub
            ]),
            ?dbg("get_key_bundle: Retrieved IdentityDHPub: ~p", [
                IdentityDHPub
            ]),
            ?dbg("get_key_bundle: Retrieved SignedPrekeyPub: ~p", [
                SignedPrekeyPub
            ]),
            ?dbg("get_key_bundle: Retrieved SignedPrekeySignature: ~p", [
                SignedPrekeySignature
            ]),

            %% key_id might not exist for upload_identity_keys flow
            KeyId = maps:get(
                key_id, IdentityData, crypto:strong_rand_bytes(16)
            ),

            %% Get OTPKs for this user
            AvailableOtpks = get_available_otpks(Username),
            ?dbg("Available OTPKs for ~p: ~p", [
                Username, length(AvailableOtpks)
            ]),

            %% Reconstruct bundle in expected format
            ReconstructedBundle = #{
                username => Username,
                key_id => KeyId,
                identity_sign_public => IdentitySignPub,
                identity_dh_public => IdentityDHPub,
                signed_prekey => #{
                    public => SignedPrekeyPub,
                    signature => SignedPrekeySignature,
                    timestamp => Timestamp
                },
                one_time_prekeys => AvailableOtpks,
                created_at => maps:get(
                    created_at, IdentityData, erlang:system_time(second)
                )
            },

            ?dbg("Successfully retrieved bundle for ~p", [
                Username
            ]),
            {ok, ReconstructedBundle};
        [] ->
            ?dbg("No key bundle found for username: ~p", [
                Username
            ]),
            {error, not_found}
    end.

%% @doc Get signed prekey with signature for verification.
%%
%% Returns the signed prekey and its signature for X3DH key agreement.
%% Implements Step 1 requirement for signed prekey verification.
%%
%% @param Username User ID
%% @returns {ok, {PrekeyPub, Signature, IdentityPub}} or {error, not_found}
-spec get_signed_prekey_with_signature(string()) ->
    {ok, {binary(), binary(), binary()}} | {error, not_found}.
get_signed_prekey_with_signature(Username) ->
    case get_key_bundle(Username) of
        {error, not_found} ->
            {error, not_found};
        {ok, BundleData} ->
            #{
                identity_sign_public := IdentitySignPub,
                signed_prekey := #{
                    public := PrekeyPub,
                    signature := Signature
                }
            } = BundleData,
            {ok, {PrekeyPub, Signature, IdentitySignPub}}
    end.

%% @doc Mark one-time prekey as consumed to ensure one-time use.
%%
%% Removes the specified OTPK from the user's prekey storage to prevent reuse.
%% Uses the new structured tuple key format for efficient lookup.
%%
%% @param Username User ID
%% @param OtpkId One-time prekey ID to mark as consumed
%% @returns ok | {error, not_found}
-spec mark_otpk_consumed(string(), binary()) -> ok | {error, not_found}.
mark_otpk_consumed(Username, OtpkId) ->
    %% Use structured tuple key for direct lookup
    KeyTuple = {Username, otpk, OtpkId},
    case ets:lookup(?PREKEY_TABLE, KeyTuple) of
        [] ->
            {error, not_found};
        [{KeyTuple, _PrekeyData}] ->
            %% Delete the consumed OTPK
            ets:delete(?PREKEY_TABLE, KeyTuple),
            ok
    end.

%% @doc Get available one-time prekeys for a user.
%%
%% Retrieves all unconsumed OTPKs for the specified user using
%% structured tuple key matching.
%%
%% @param Username User ID
%% @returns List of available OTPK data maps
-spec get_available_otpks(string()) -> [map()].
get_available_otpks(Username) ->
    %% Use ets:match to find all OTPKs for this user
    Pattern = {{Username, otpk, '_'}, '$1'},
    Matches = ets:match(?PREKEY_TABLE, Pattern),
    [
        #{
            id => maps:get(key_id, PrekeyData),
            public => maps:get(public_key, PrekeyData)
            %% Note: private key not stored on server for security
        }
     || [PrekeyData] <- Matches, not maps:get(consumed, PrekeyData, false)
    ].

%% @doc Get key status information for a user.
%%
%% Returns summary information about the keys stored for a user:
%% - Identity key presence
%% - Signed prekey information
%% - One-time prekeys count
%% - Key bundle creation timestamp
%%
%% @param Username The username to get key status for
%% @returns {ok, map()} with key status information, or {error, not_found}
-spec get_key_status(string()) -> {ok, map()} | {error, not_found}.
get_key_status(Username) ->
    %% Look for identity entry in PREKEY_TABLE
    case ets:lookup(?PREKEY_TABLE, {Username, identity}) of
        [{{Username, identity}, IdentityData}] ->
            %% Count available OTPKs
            AvailableOtpks = get_available_otpks(Username),
            OtpkCount = length(AvailableOtpks),

            %% Extract signed prekey timestamp
            SignedPrekeyTimestamp = maps:get(
                timestamp,
                maps:get(signed_prekey, IdentityData, #{}),
                erlang:system_time(second)
            ),

            %% Get creation timestamp
            CreatedAt = maps:get(
                created_at, IdentityData, erlang:system_time(second)
            ),

            %% Build status response
            Status = #{
                username => Username,
                has_identity_keys => true,
                has_signed_prekey => true,
                signed_prekey_timestamp => SignedPrekeyTimestamp,
                otpk_count => OtpkCount,
                created_at => CreatedAt
            },

            {ok, Status};
        [] ->
            %% Check if user has any keys at all
            Pattern = {{Username, '_', '_'}, '_'},
            case ets:match(?PREKEY_TABLE, Pattern, 1) of
                {[_], _} ->
                    %% User has some keys but no complete identity
                    {ok, #{
                        username => Username,
                        has_identity_keys => false,
                        has_signed_prekey => false,
                        otpk_count => 0,
                        status => incomplete_setup
                    }};
                '$end_of_table' ->
                    %% No keys found for user
                    {error, not_found}
            end
    end.

%% @doc Get next sequence number for a communication pair.
%%
%% Retrieves and increments the sequence number for messages from SenderID to RecipientID.
%% Sequence numbers are used to prevent replay attacks and ensure message ordering.
%%
%% @param SenderID Sender's user ID
%% @param RecipientID Recipient's user ID
%% @returns Next sequence number (integer >= 1)
-spec get_next_sequence(binary(), binary()) -> non_neg_integer().
get_next_sequence(SenderID, RecipientID) ->
    Key = {SenderID, RecipientID},
    case ets:lookup(?SEQUENCE_TABLE, Key) of
        [] ->
            %% First message between these users
            ets:insert(?SEQUENCE_TABLE, {Key, 1}),
            1;
        [{Key, CurrentSeq}] ->
            NextSeq = CurrentSeq + 1,
            ets:insert(?SEQUENCE_TABLE, {Key, NextSeq}),
            NextSeq
    end.

%% @doc Validate sequence number for replay protection.
%%
%% Checks if the received sequence number is valid (not a replay) for the
%% communication pair. Allows out-of-order delivery within a reasonable window.
%%
%% @param SenderID Sender's user ID
%% @param RecipientID Recipient's user ID (should be local user)
%% @param ReceivedSeq Sequence number from received message
%% @returns true if sequence is valid, false if it's a replay
-spec validate_sequence(binary(), binary(), non_neg_integer()) -> boolean().
validate_sequence(SenderID, RecipientID, ReceivedSeq) ->
    Key = {SenderID, RecipientID},
    case ets:lookup(?SEQUENCE_TABLE, Key) of
        [] ->
            %% First message from this sender - any positive sequence is valid
            ReceivedSeq > 0;
        [{Key, LastSeq}] ->
            %% For simplicity: reject sequences that are too old
            %% Allow small window for out-of-order delivery

            % Allow sequences up to 3 behind the latest
            Window = 3,
            ReceivedSeq > LastSeq - Window
    end.

%% @doc Update sequence number after successful message processing.
%%
%% Updates the stored sequence number for received messages to prevent replay.
%% Only updates if the received sequence is higher than current.
%%
%% @param SenderID Sender's user ID
%% @param RecipientID Recipient's user ID (should be local user)
%% @param ReceivedSeq Sequence number from successfully processed message
%% @returns ok
-spec update_sequence(binary(), binary(), non_neg_integer()) -> ok.
update_sequence(SenderID, RecipientID, ReceivedSeq) ->
    Key = {SenderID, RecipientID},
    case ets:lookup(?SEQUENCE_TABLE, Key) of
        [] ->
            ets:insert(?SEQUENCE_TABLE, {Key, ReceivedSeq});
        [{Key, LastSeq}] when ReceivedSeq > LastSeq ->
            ets:insert(?SEQUENCE_TABLE, {Key, ReceivedSeq});
        _ ->
            %% Don't update if sequence is older or equal
            ok
    end,
    ok.

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
    ensure_table(?SEQUENCE_TABLE),
    ok.

ensure_table(TableName) ->
    case ets:info(TableName) of
        undefined ->
            ets:new(TableName, [named_table, public, set]);
        _ ->
            ok
    end.
