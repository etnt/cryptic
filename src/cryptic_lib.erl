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

gen_keypair() ->
    %% Our NIF returns {Public, Secret}
    cryptic_nif:gen_keypair().

scalarmult(Priv, Pub) ->
    %% X25519 scalar multiplication via our NIF
    cryptic_nif:scalarmult(Priv, Pub).

aead_encrypt(Plain, Key, AAD) ->
    %% Use ChaCha20-Poly1305 IETF via our NIF
    %% NIF generates nonce internally and returns {Cipher, Nonce}
    cryptic_nif:aead_encrypt(Plain, Key, AAD).

aead_decrypt(Cipher, Key, Nonce, AAD) ->
    %% ChaCha20-Poly1305 IETF decryption via our NIF
    cryptic_nif:aead_decrypt(Cipher, Key, Nonce, AAD).

rand_bytes(N) ->
    %% Generate cryptographically secure random bytes via our NIF
    cryptic_nif:rand_bytes(N).

%% HKDF-SHA256 key derivation
hkdf_sha256(IKM, Info, L) ->
    hkdf_sha256(IKM, <<>>, Info, L).

%% HKDF-SHA256 with explicit salt parameter  
hkdf_sha256(IKM, Salt, Info, L) ->
    PRK = crypto:mac(hmac, sha256, Salt, IKM),
    T1 = crypto:mac(hmac, sha256, PRK, <<Info/binary, 1:8>>),
    %% For 32-byte output, single iteration is sufficient
    binary:part(T1, 0, L).

%% Derive AEAD key with random salt (most secure)
derive_aead_key_random(SharedSecret) ->
    Salt = rand_bytes(32),
    AeadKey = hkdf_sha256(SharedSecret, Salt, <<"encryption">>, 32),
    {AeadKey, Salt}.

%% Derive AEAD key with ephemeral-based salt (good compromise)
derive_aead_key_ephemeral(SharedSecret, EphemeralPubKey) ->
    Salt = crypto:hash(sha256, EphemeralPubKey),
    hkdf_sha256(SharedSecret, Salt, <<"encryption">>, 32).

%% Derive AEAD key with empty salt (current approach - least secure)
derive_aead_key_simple(SharedSecret) ->
    hkdf_sha256(SharedSecret, <<"encryption">>, 32).
