#include <erl_nif.h>
#include <sodium.h>
#include <string.h>

// NIF resource types
static ErlNifResourceType *keypair_type = NULL;

// Initialize libsodium
static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    if (sodium_init() < 0)
    {
        return -1;
    }

    keypair_type = enif_open_resource_type(env, NULL, "keypair", NULL,
                                           ERL_NIF_RT_CREATE, NULL);
    if (keypair_type == NULL)
    {
        return -1;
    }

    return 0;
}

// Generate X25519 keypair
static ERL_NIF_TERM gen_keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(pk, sk);

    ERL_NIF_TERM public_key, secret_key;
    unsigned char *pk_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &public_key);
    unsigned char *sk_data = enif_make_new_binary(env, crypto_box_SECRETKEYBYTES, &secret_key);

    memcpy(pk_data, pk, crypto_box_PUBLICKEYBYTES);
    memcpy(sk_data, sk, crypto_box_SECRETKEYBYTES);

    // Clear sensitive data
    sodium_memzero(sk, crypto_box_SECRETKEYBYTES);

    return enif_make_tuple2(env, public_key, secret_key);
}

// X25519 scalar multiplication
static ERL_NIF_TERM scalarmult(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary secret_key, public_key;

    if (!enif_inspect_binary(env, argv[0], &secret_key) ||
        !enif_inspect_binary(env, argv[1], &public_key) ||
        secret_key.size != crypto_scalarmult_SCALARBYTES ||
        public_key.size != crypto_scalarmult_BYTES)
    {
        return enif_make_badarg(env);
    }

    unsigned char shared_secret[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(shared_secret, secret_key.data, public_key.data) != 0)
    {
        return enif_make_atom(env, "error");
    }

    ERL_NIF_TERM result;
    unsigned char *result_data = enif_make_new_binary(env, crypto_scalarmult_BYTES, &result);
    memcpy(result_data, shared_secret, crypto_scalarmult_BYTES);

    // Clear sensitive data
    sodium_memzero(shared_secret, crypto_scalarmult_BYTES);

    return result;
}

// ChaCha20-Poly1305 AEAD encryption
static ERL_NIF_TERM aead_encrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary plaintext, key, aad;

    if (!enif_inspect_binary(env, argv[0], &plaintext) ||
        !enif_inspect_binary(env, argv[1], &key) ||
        !enif_inspect_binary(env, argv[2], &aad) ||
        key.size != crypto_aead_chacha20poly1305_ietf_KEYBYTES)
    {
        return enif_make_badarg(env);
    }

    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    unsigned char *ciphertext = malloc(plaintext.size + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;

    if (ciphertext == NULL)
    {
        return enif_make_atom(env, "error");
    }

    // Generate random nonce
    randombytes_buf(nonce, sizeof(nonce));

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext, &ciphertext_len,
            plaintext.data, plaintext.size,
            aad.data, aad.size,
            NULL, nonce, key.data) != 0)
    {
        free(ciphertext);
        return enif_make_atom(env, "error");
    }

    ERL_NIF_TERM cipher_term, nonce_term;
    unsigned char *cipher_data = enif_make_new_binary(env, ciphertext_len, &cipher_term);
    unsigned char *nonce_data = enif_make_new_binary(env, sizeof(nonce), &nonce_term);

    memcpy(cipher_data, ciphertext, ciphertext_len);
    memcpy(nonce_data, nonce, sizeof(nonce));

    free(ciphertext);

    return enif_make_tuple2(env, cipher_term, nonce_term);
}

// ChaCha20-Poly1305 AEAD decryption
static ERL_NIF_TERM aead_decrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ciphertext, key, nonce, aad;

    if (!enif_inspect_binary(env, argv[0], &ciphertext) ||
        !enif_inspect_binary(env, argv[1], &key) ||
        !enif_inspect_binary(env, argv[2], &nonce) ||
        !enif_inspect_binary(env, argv[3], &aad) ||
        key.size != crypto_aead_chacha20poly1305_ietf_KEYBYTES ||
        nonce.size != crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
    {
        return enif_make_badarg(env);
    }

    if (ciphertext.size < crypto_aead_chacha20poly1305_ietf_ABYTES)
    {
        return enif_make_atom(env, "error");
    }

    unsigned char *plaintext = malloc(ciphertext.size - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len;

    if (plaintext == NULL)
    {
        return enif_make_atom(env, "error");
    }

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &plaintext_len,
            NULL,
            ciphertext.data, ciphertext.size,
            aad.data, aad.size,
            nonce.data, key.data) != 0)
    {
        free(plaintext);
        return enif_make_atom(env, "error");
    }

    ERL_NIF_TERM result;
    unsigned char *result_data = enif_make_new_binary(env, plaintext_len, &result);
    memcpy(result_data, plaintext, plaintext_len);

    free(plaintext);

    return result;
}

// Generate random bytes
static ERL_NIF_TERM rand_bytes(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int size;

    if (!enif_get_int(env, argv[0], &size) || size < 0 || size > 1024)
    {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM result;
    unsigned char *data = enif_make_new_binary(env, size, &result);
    randombytes_buf(data, size);

    return result;
}

// NIF function exports
static ErlNifFunc nif_funcs[] = {
    {"gen_keypair", 0, gen_keypair, 0},
    {"scalarmult", 2, scalarmult, 0},
    {"aead_encrypt", 3, aead_encrypt, 0},
    {"aead_decrypt", 4, aead_decrypt, 0},
    {"rand_bytes", 1, rand_bytes, 0}};

ERL_NIF_INIT(cryptic_nif, nif_funcs, load, NULL, NULL, NULL)
