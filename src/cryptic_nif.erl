%%% @doc Cryptic NIF Interface
%%%
%%% This module provides Erlang NIFs (Native Implemented Functions) for
%%% cryptographic operations used by the Cryptic chat application. It serves
%%% as the interface layer between Erlang code and the underlying C/C++
%%% cryptographic library implementations.
%%%
%%% == Features ==
%%%
%%% <ul>
%%%   <li>Curve25519 elliptic curve cryptography for key exchange</li>
%%%   <li>ChaCha20-Poly1305 authenticated encryption (AEAD)</li>
%%%   <li>Cryptographically secure random number generation</li>
%%%   <li>High-performance native cryptographic primitives</li>
%%%   <li>Memory-safe NIF implementations</li>
%%% </ul>
%%%
%%% == Cryptographic Operations ==
%%%
%%% The module provides the following cryptographic primitives:
%%% <ul>
%%%   <li>`gen_keypair/0' - Generate Curve25519 key pairs</li>
%%%   <li>`scalarmult/2' - Elliptic curve scalar multiplication (ECDH)</li>
%%%   <li>`aead_encrypt/3' - ChaCha20-Poly1305 authenticated encryption</li>
%%%   <li>`aead_decrypt/4' - ChaCha20-Poly1305 authenticated decryption</li>
%%%   <li>`rand_bytes/1' - Cryptographically secure random bytes</li>
%%% </ul>
%%%
%%% == Security Notes ==
%%%
%%% <ul>
%%%   <li>All cryptographic operations are performed in native code for performance</li>
%%%   <li>Memory is properly zeroed after use to prevent key material leakage</li>
%%%   <li>Random number generation uses the system's secure random source</li>
%%%   <li>Key material should be handled securely in calling code</li>
%%% </ul>
%%%
%%% == NIF Loading ==
%%%
%%% The module uses the `@on_load' attribute to automatically load the
%%% shared library containing the NIF implementations. The library is
%%% searched in standard priv directory locations.
%%%
%%% @author Cryptic Team
%%% @version 1.0.0
%%% @since 2025-09-14

-module(cryptic_nif).

-export([
    init/0,
    gen_keypair/0,
    scalarmult/2,
    aead_encrypt/3,
    aead_decrypt/4,
    rand_bytes/1,
    ed25519_sk_to_x25519_sk/1,
    ed25519_pk_to_x25519_pk/1,
    kdf_derive/4,
    hkdf_sha256/4,
    argon2id_raw/6
]).

-on_load(init/0).

-define(APPNAME, cryptic).
-define(LIBNAME, cryptic_nif).

%% @doc Initialize and load the NIF library
%%
%% This function is called automatically when the module is loaded due to
%% the `@on_load' attribute. It locates the shared library containing the
%% NIF implementations and loads it into the Erlang VM.
%%
%% == Library Search Process ==
%%
%% The function searches for the library in the following locations:
%% <ol>
%%%   <li>Application's priv directory (standard location)</li>
%%%   <li>Relative "../priv" directory (development builds)</li>
%%%   <li>Local "priv" directory (fallback)</li>
%% </ol>
%%
%% @returns ok if the NIF library loads successfully
%% @throws {error, any()}

init() ->
    SoName =
        case code:priv_dir(?APPNAME) of
            {error, bad_name} ->
                case filelib:is_dir(filename:join(["..", priv])) of
                    true ->
                        filename:join(["..", priv, ?LIBNAME]);
                    _ ->
                        filename:join([priv, ?LIBNAME])
                end;
            Dir ->
                filename:join(Dir, ?LIBNAME)
        end,
    erlang:load_nif(SoName, 0).

%% @doc Generate a Curve25519 key pair
%%
%% Generates a new Curve25519 elliptic curve key pair suitable for
%% Elliptic Curve Diffie-Hellman (ECDH) key exchange. The private key
%% should be kept secret while the public key can be shared.
%%
%% == Security Considerations ==
%%
%% <ul>
%%%   <li>Private keys must be kept secure and never transmitted</li>
%%%   <li>Public keys can be safely shared for key exchange</li>
%%%   <li>Keys are generated using cryptographically secure randomness</li>
%%%   <li>Private key material is properly handled in native code</li>
%% </ul>
%%
%% @returns {PublicKey, PrivateKey} where both are 32-byte binaries
%% @throws {error, atom()} | {nif_not_loaded, atom()}
gen_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%% @doc Perform Curve25519 scalar multiplication (ECDH)
%%
%% Computes the shared secret between a private key and a public key
%% using Curve25519 elliptic curve scalar multiplication. This is the
%% core operation for Elliptic Curve Diffie-Hellman key exchange.
%%
%% == Usage Pattern ==
%%
%% ```
%% % Alice generates her key pair
%% {AlicePub, AlicePriv} = cryptic_nif:gen_keypair(),
%%
%% % Bob generates his key pair
%% {BobPub, BobPriv} = cryptic_nif:gen_keypair(),
%%
%% % Both parties compute the same shared secret
%% SharedSecret1 = cryptic_nif:scalarmult(AlicePriv, BobPub),
%% SharedSecret2 = cryptic_nif:scalarmult(BobPriv, AlicePub),
%% % SharedSecret1 =:= SharedSecret2
%% '''
%%
%% == Security Notes ==
%%
%% <ul>
%%%   <li>The shared secret should be used as input to a key derivation function</li>
%%%   <li>Never use the shared secret directly as an encryption key</li>
%%%   <li>Private keys must be exactly 32 bytes</li>
%%%   <li>Public keys must be exactly 32 bytes and on the curve</li>
%% </ul>
%%
%% @param SecretKey The private key (32-byte binary)
%% @param PublicKey The peer's public key (32-byte binary)
%% @returns SharedSecret A 32-byte binary containing the shared secret
%% @throws {error, atom()} | {nif_not_loaded, atom()}

scalarmult(_SecretKey, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%% @doc Encrypt data using ChaCha20-Poly1305 AEAD
%%
%% Performs authenticated encryption using the ChaCha20-Poly1305 AEAD
%% (Authenticated Encryption with Associated Data) algorithm. This provides
%% both confidentiality and authenticity for the encrypted data.
%%
%% == Algorithm Details ==
%%
%% <ul>
%%%   <li>Encryption: ChaCha20 stream cipher</li>
%%%   <li>Authentication: Poly1305 MAC</li>
%%%   <li>Nonce: 12-byte random value (generated automatically)</li>
%%%   <li>Key: 32-byte encryption key</li>
%%%   <li>AAD: Additional authenticated data (not encrypted)</li>
%% </ul>
%%
%% == Usage Example ==
%%
%% ```
%% Key = cryptic_nif:rand_bytes(32),
%% Plaintext = <<"Hello, World!">>,
%% AAD = <<"metadata">>,
%% {Nonce, Ciphertext} = cryptic_nif:aead_encrypt(Plaintext, Key, AAD).
%% '''
%%
%% == Security Notes ==
%%
%% <ul>
%%%   <li>Never reuse the same key+nonce combination</li>
%%%   <li>Nonce is generated randomly and must be transmitted with ciphertext</li>
%%%   <li>AAD is authenticated but not encrypted</li>
%%%   <li>Tampering with ciphertext or AAD will cause decryption to fail</li>
%% </ul>
%%
%% @param Plaintext The data to encrypt (binary)
%% @param Key The 32-byte encryption key (binary)
%% @param AAD Additional authenticated data (binary, can be empty)
%% @returns {Nonce, Ciphertext} where Nonce is 12 bytes and Ciphertext includes auth tag
%% @throws {error, atom()} | {nif_not_loaded, atom()}

aead_encrypt(_Plaintext, _Key, _AAD) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%% @doc Decrypt data using ChaCha20-Poly1305 AEAD
%%
%% Performs authenticated decryption using the ChaCha20-Poly1305 AEAD
%% algorithm. Verifies both the authenticity and integrity of the encrypted
%% data before returning the plaintext.
%%
%% == Verification Process ==
%%
%% <ol>
%%%   <li>Verify the Poly1305 authentication tag</li>
%%%   <li>Verify the AAD has not been tampered with</li>
%%%   <li>Decrypt the ciphertext using ChaCha20</li>
%%%   <li>Return plaintext only if all verifications pass</li>
%% </ol>
%%
%% == Usage Example ==
%%
%% ```
%% % Using data from aead_encrypt/3
%% case cryptic_nif:aead_decrypt(Ciphertext, Key, Nonce, AAD) of
%%     {ok, Plaintext} ->
%%         % Decryption successful, data is authentic
%%         process_plaintext(Plaintext);
%%     {error, auth_failed} ->
%%         % Data has been tampered with or wrong key/nonce
%%         handle_auth_failure()
%% end.
%% '''
%%
%% == Security Notes ==
%%
%% <ul>
%%%   <li>Always check the return value - authentication failure indicates tampering</li>
%%%   <li>Use the exact same key, nonce, and AAD that were used for encryption</li>
%%%   <li>Never attempt to process data if authentication fails</li>
%%%   <li>Timing attacks are mitigated by constant-time verification</li>
%% </ul>
%%
%% @param Ciphertext The encrypted data including authentication tag (binary)
%% @param Key The 32-byte decryption key (binary)
%% @param Nonce The 12-byte nonce used during encryption (binary)
%% @param AAD The additional authenticated data (binary, must match encryption)
%% @returns {ok, Plaintext} on successful decryption and authentication,
%%          {error, auth_failed} if authentication fails
%% @throws {error, atom()} | {nif_not_loaded, atom()}

aead_decrypt(_Ciphertext, _Key, _Nonce, _AAD) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%% @doc Generate cryptographically secure random bytes
%%
%% Generates the specified number of cryptographically secure random bytes
%% using the system's secure random number generator. This function is
%% suitable for generating keys, nonces, salts, and other security-critical
%% random data.
%%
%% == Random Source ==
%%
%% <ul>
%%%   <li>Uses the operating system's secure random number generator</li>
%%%   <li>On Linux: /dev/urandom or getrandom() syscall</li>
%%%   <li>On macOS: SecRandomCopyBytes or /dev/urandom</li>
%%%   <li>On Windows: CryptGenRandom or BCryptGenRandom</li>
%% </ul>
%%
%% == Usage Examples ==
%%
%% ```
%% % Generate a 32-byte encryption key
%% Key = cryptic_nif:rand_bytes(32),
%%
%% % Generate a 12-byte nonce
%% Nonce = cryptic_nif:rand_bytes(12),
%%
%% % Generate a random salt
%% Salt = cryptic_nif:rand_bytes(16).
%% '''
%%
%% == Security Notes ==
%%
%% <ul>
%%%   <li>Output is suitable for cryptographic purposes</li>
%%%   <li>No need to seed - uses system entropy</li>
%%%   <li>Non-blocking operation in most cases</li>
%%%   <li>Returns different values on each call</li>
%% </ul>
%%
%% @param Size The number of random bytes to generate (positive integer)
%% @returns Binary containing the requested number of random bytes
%% @throws {error, atom()} | {nif_not_loaded, atom()}

rand_bytes(_Size) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%% @doc Convert Ed25519 private key to X25519 private key
%%
%% Performs a secure conversion from an Ed25519 signing private key to an
%% X25519 ECDH private key using libsodium's crypto_sign_ed25519_sk_to_curve25519.
%% This conversion is mathematically sound and preserves the cryptographic
%% relationship between the keys.
%%
%% == Usage ==
%%
%% ```
%% {Ed25519Pub, Ed25519Priv} = crypto:generate_key(eddsa, ed25519),
%% X25519Priv = cryptic_nif:ed25519_sk_to_x25519_sk(Ed25519Priv).
%% '''
%%
%% == Security Notes ==
%%
%% <ul>
%%%   <li>The conversion is deterministic - same Ed25519 key produces same X25519 key</li>
%%%   <li>The converted key is cryptographically valid for X25519 operations</li>
%%%   <li>Both keys should be treated with equal security precautions</li>
%% </ul>
%%
%% @param Ed25519SecretKey The Ed25519 private key (32-byte binary)
%% @returns X25519 private key (32-byte binary)
%% @throws {error, atom()} | {nif_not_loaded, atom()}
ed25519_sk_to_x25519_sk(_Ed25519SecretKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%% @doc Convert Ed25519 public key to X25519 public key
%%
%% Performs a secure conversion from an Ed25519 signing public key to an
%% X25519 ECDH public key using libsodium's crypto_sign_ed25519_pk_to_curve25519.
%% This conversion maintains the mathematical relationship between the corresponding
%% private keys.
%%
%% == Usage ==
%%
%% ```
%% {Ed25519Pub, Ed25519Priv} = crypto:generate_key(eddsa, ed25519),
%% X25519Pub = cryptic_nif:ed25519_pk_to_x25519_pk(Ed25519Pub).
%% '''
%%
%% == Security Notes ==
%%
%% <ul>
%%%   <li>The conversion is deterministic and publicly computable</li>
%%%   <li>Both public keys can be safely shared</li>
%%%   <li>The converted X25519 key corresponds to the converted private key</li>
%% </ul>
%%
%% @param Ed25519PublicKey The Ed25519 public key (32-byte binary)
%% @returns X25519 public key (32-byte binary)
%% @throws {error, atom()} | {nif_not_loaded, atom()}
ed25519_pk_to_x25519_pk(_Ed25519PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%% @doc Derive key material using libsodium's KDF (Blake2b-based)
%%
%% High-performance key derivation using libsodium's crypto_kdf_derive_from_key
%% function. This is optimized for symmetric key ratcheting where many keys
%% need to be derived quickly from a master key.
%%
%% == Ratcheting Usage ==
%%
%% ```
%% % Initialize with root key
%% RootKey = cryptic_nif:rand_bytes(32),
%% Context = <<"ratchet">>,
%%
%% % Derive chain keys with incrementing IDs
%% ChainKey1 = cryptic_nif:kdf_derive(32, 1, Context, RootKey),
%% ChainKey2 = cryptic_nif:kdf_derive(32, 2, Context, RootKey),
%% MessageKey1 = cryptic_nif:kdf_derive(32, 1, <<"msg">>, ChainKey1).
%% '''
%%
%% == Performance Notes ==
%%
%% <ul>
%%%   <li>Faster than HKDF-SHA256 for high-frequency operations</li>
%%%   <li>Uses Blake2b internally which is optimized for speed</li>
%%%   <li>Perfect for Double Ratchet message key derivation</li>
%%%   <li>Constant-time operation prevents timing attacks</li>
%% </ul>
%%
%% == Security Properties ==
%%
%% <ul>
%%%   <li>Cryptographically secure key separation by SubkeyId</li>
%%%   <li>Context provides domain separation (max 8 bytes)</li>
%%%   <li>Different SubkeyId values produce independent keys</li>
%%%   <li>Cannot derive master key from any derived keys</li>
%% </ul>
%%
%% @param Length Length of derived key in bytes (1-64)
%% @param SubkeyId Unique identifier for this derived key (0-2^64-1)
%% @param Context Domain separation context (max 8 bytes)
%% @param MasterKey Master key material (32 bytes)
%% @returns Derived key binary of specified length
%% @throws {error, atom()} | {nif_not_loaded, atom()}
kdf_derive(_Length, _SubkeyId, _Context, _MasterKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%% @doc HKDF-SHA256 key derivation (RFC 5869 compliant)
%%
%% Standard HKDF-SHA256 implementation for compatibility with existing
%% protocols and systems that specifically require RFC 5869 HKDF.
%% For new applications, consider kdf_derive/4 which is faster.
%%
%% == Protocol Compatibility ==
%%
%% ```
%% % X3DH shared secret expansion
%% SharedSecret = cryptic_nif:scalarmult(PrivKey, PubKey),
%% Salt = <<"X3DH">>,
%% Info = <<"encryption_key">>,
%% EncKey = cryptic_nif:hkdf_sha256(SharedSecret, Salt, Info, 32).
%% '''
%%
%% == RFC 5869 Process ==
%%
%% <ol>
%%%   <li>Extract: PRK = HMAC-SHA256(Salt, IKM)</li>
%%%   <li>Expand: OKM = HMAC-SHA256(PRK, Info || Counter)</li>
%% </ol>
%%
%% == Security Notes ==
%%
%% <ul>
%%%   <li>Salt should be random or at least unique per protocol run</li>
%%%   <li>Info provides context and domain separation</li>
%%%   <li>Same IKM+Salt+Info always produces same output (deterministic)</li>
%%%   <li>Current implementation supports up to 32-byte output</li>
%% </ul>
%%
%% @param IKM Input keying material (e.g., ECDH shared secret)
%% @param Salt Salt value for extraction phase (can be an empty binary)
%% @param Info Context and application-specific information
%% @param Length Length of output keying material (1-32 bytes)
%% @returns Derived key material of specified length
%% @throws {error, atom()} | {nif_not_loaded, atom()}
hkdf_sha256(_IKM, _Salt, _Info, _Length) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

%% @doc Derive raw key material using Argon2id (libargon2)
%%
%% Computes an Argon2id (version 1.3) hash with a fully configurable parameter
%% set. Unlike a general password-hashing helper, this exposes `Parallelism'
%% because the enrollment package format produced by `bin/cryptic-onboard'
%% uses the `argon2' CLI with a lane count of 4, which the libsodium
%% high-level `crypto_pwhash' API cannot reproduce.
%%
%% == Usage ==
%%
%% ```
%% %% Mirrors: argon2 <Salt> -id -t 3 -m 16 -p 4 -l 64 -r
%% Derived = cryptic_nif:argon2id_raw(Passphrase, Salt, 3, 65536, 4, 64).
%% '''
%%
%% == Parameters ==
%%
%% <ul>
%%   <li>`MemoryKiB' is the memory cost in kibibytes. The CLI `-m N' flag
%%       corresponds to `2^N' KiB, so `-m 16' means pass `65536'.</li>
%%   <li>`Salt' is used verbatim as the Argon2 salt (must be &gt;= 8 bytes).</li>
%% </ul>
%%
%% @param Password The secret input (binary)
%% @param Salt The salt bytes (binary, at least 8 bytes)
%% @param TimeCost Number of iterations (&gt;= 1)
%% @param MemoryKiB Memory cost in kibibytes
%% @param Parallelism Number of lanes/threads (&gt;= 1)
%% @param HashLen Length of the derived output in bytes (4-1024)
%% @returns Raw derived key material of `HashLen' bytes
%% @throws {error, atom()} | {nif_not_loaded, atom()}
argon2id_raw(_Password, _Salt, _TimeCost, _MemoryKiB, _Parallelism, _HashLen) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).