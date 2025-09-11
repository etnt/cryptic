-module(cryptic_lib).

-export([gen_keypair/0, scalarmult/2, aead_encrypt/3, aead_decrypt/3, rand_bytes/1]).

%% Use salty NIF functions (wraps libsodium)
%% gen_keypair returns {PubBin, PrivBin} for X25519 using crypto_box_keypair-style

gen_keypair() ->
    %% salty:crypto_box_keypair returns {Public, Secret}
    {Pub, Sec} = salty:crypto_box_keypair(),
    {Pub, Sec}.

scalarmult(Priv, Pub) ->
    %% X25519 scalar multiplication: salty:crypto_scalarmult
    %% salty uses binary buffers
    salty:crypto_scalarmult(Priv, Pub).

aead_encrypt(Plain, Key, AAD) ->
    %% Use XChaCha20-Poly1305 IETF (24-byte nonce)
    Nonce = rand_bytes(24),
    Cipher = salty:crypto_aead_xchacha20poly1305_ietf_encrypt(Plain, AAD, Nonce, Key),
    {Cipher, Nonce}.

aead_decrypt(Cipher, Key, Nonce, AAD) ->
    salty:crypto_aead_xchacha20poly1305_ietf_decrypt(Cipher, AAD, Nonce, Key).

rand_bytes(N) ->
    salty:randombytes_buf(N).
