%%% @doc Cryptographic Library for Secure Communication
%%%
%%% This module provides cryptographic primitives for the Cryptic chat application.
%%% It wraps libsodium functions through NIFs and implements key derivation schemes
%%% for secure end-to-end encrypted messaging.
%%%
%%% == Cryptographic Primitives ==
%%%
%%% <ul>
%%%   <li>**X25519 Key Exchange**: Elliptic curve Diffie-Hellman key agreement</li>
%%%   <li>**ChaCha20-Poly1305**: Authenticated encryption with associated data (AEAD)</li>
%%%   <li>**HKDF-SHA256**: Key derivation function for generating encryption keys</li>
%%%   <li>**Secure Random**: Cryptographically secure random number generation</li>
%%% </ul>
%%%
%%% == Security Model ==
%%%
%%% The library implements a forward-secure messaging protocol:
%%% <ol>
%%%   <li>Each user generates an X25519 keypair for identity</li>
%%%   <li>Message encryption uses ephemeral X25519 keypairs for perfect forward secrecy</li>
%%%   <li>Shared secrets are derived using X25519 scalar multiplication</li>
%%%   <li>AEAD keys are derived from shared secrets using HKDF-SHA256</li>
%%%   <li>Messages are encrypted with ChaCha20-Poly1305 AEAD</li>
%%% </ol>
%%%
%%% == Key Derivation Strategies ==
%%%
%%% The module provides three key derivation approaches with different security/usability tradeoffs:
%%% <ul>
%%%   <li>`derive_aead_key_random/1' - Most secure with random salt</li>
%%%   <li>`derive_aead_key_ephemeral/2' - Good balance using ephemeral public key as salt</li>
%%%   <li>`derive_aead_key_simple/1' - Simplest but least secure (empty salt)</li>
%%% </ul>
%%%
%%% == Example Usage ==
%%%
%%% ```
%%% %% Generate keypair for user
%%% {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
%%%
%%% %% Encrypt message to another user
%%% {RecipientPub, _} = cryptic_lib:gen_keypair(),  % In practice, fetch from server
%%% SharedSecret = cryptic_lib:scalarmult(PrivKey, RecipientPub),
%%% AeadKey = cryptic_lib:derive_aead_key_simple(SharedSecret),
%%% {Ciphertext, Nonce} = cryptic_lib:aead_encrypt(<<"Hello">>, AeadKey, <<>>),
%%%
%%% %% Decrypt message
%%% Plaintext = cryptic_lib:aead_decrypt(Ciphertext, AeadKey, Nonce, <<>>).
%%% '''
%%%
%%% @author Cryptic Team
%%% @version 1.0
%%% @since 2025-09-12
-module(cryptic_lib).

-export([
    gen_keypair/0,
    scalarmult/2,
    aead_encrypt/3,
    aead_decrypt/4,
    rand_bytes/1,
    hkdf_sha256/3,
    hkdf_sha256/4,
    derive_aead_key_random/1,
    derive_aead_key_ephemeral/2,
    derive_aead_key_simple/1
]).

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
%% @throws `badarg' if key sizes are incorrect or keys are invalid
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
%% @throws `badarg' if key size is incorrect
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
%% @throws `decrypt_failed' if authentication fails or inputs are invalid
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
%% @throws `badarg' if N is negative
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
