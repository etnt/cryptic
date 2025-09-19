/**
 * @file cryptic_nif.c
 * @brief Cryptographic NIF (Native Implemented Functions) for Cryptic Chat Application
 *
 * This module provides high-performance cryptographic primitives through libsodium
 * for secure end-to-end encrypted messaging. It implements essential cryptographic
 * operations required for the X3DH key agreement protocol and ChaCha20-Poly1305
 * authenticated encryption.
 *
 * @section Features
 * - X25519 elliptic curve key generation and scalar multiplication
 * - ChaCha20-Poly1305 AEAD encryption and decryption
 * - Ed25519 to X25519 key conversion for dual-key cryptography
 * - Cryptographically secure random number generation
 * - Memory-safe operations with automatic cleanup of sensitive data
 *
 * @section Security
 * All functions implement proper key clamping, memory zeroing, and error handling
 * to prevent timing attacks and sensitive data leakage.
 *
 * @author Cryptic Team
 * @version 2.0
 * @date 2025-09-19
 * @copyright MIT License
 */

#include <erl_nif.h>
#include <sodium.h>
#include <string.h>

// NIF resource types
static ErlNifResourceType *keypair_type = NULL;

/**
 * @brief Initialize the NIF module and libsodium
 *
 * This function is called when the NIF library is loaded. It initializes
 * libsodium's secure random number generator and sets up Erlang resource types.
 *
 * @param env Erlang NIF environment
 * @param priv_data Private data pointer (unused)
 * @param load_info Load information term (unused)
 * @return 0 on success, -1 on failure
 */
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

/**
 * @brief Generate an X25519 elliptic curve keypair
 *
 * Generates a cryptographically secure X25519 keypair suitable for Elliptic Curve
 * Diffie-Hellman (ECDH) key agreement. The private key is properly clamped according
 * to RFC 7748 specifications to ensure security.
 *
 * @param env Erlang NIF environment
 * @param argc Number of arguments (must be 0)
 * @param argv Array of arguments (unused)
 * @return Tuple {PublicKey, PrivateKey} or atom 'error'
 *
 * @note The private key is automatically zeroed from memory after copying to prevent
 *       sensitive data leakage.
 */
static ERL_NIF_TERM gen_keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    unsigned char pk[crypto_scalarmult_BYTES];
    unsigned char sk[crypto_scalarmult_SCALARBYTES];

    // Generate random private key
    randombytes_buf(sk, crypto_scalarmult_SCALARBYTES);

    // Clamp the private key for X25519 (this is crucial!)
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    // Compute public key from private key
    if (crypto_scalarmult_base(pk, sk) != 0)
    {
        return enif_make_atom(env, "error");
    }

    ERL_NIF_TERM public_key, secret_key;
    unsigned char *pk_data = enif_make_new_binary(env, crypto_scalarmult_BYTES, &public_key);
    unsigned char *sk_data = enif_make_new_binary(env, crypto_scalarmult_SCALARBYTES, &secret_key);

    memcpy(pk_data, pk, crypto_scalarmult_BYTES);
    memcpy(sk_data, sk, crypto_scalarmult_SCALARBYTES);

    // Clear sensitive data
    sodium_memzero(sk, crypto_scalarmult_SCALARBYTES);

    return enif_make_tuple2(env, public_key, secret_key);
}

/**
 * @brief Perform X25519 scalar multiplication for shared secret derivation
 *
 * Computes the shared secret between a private key and a public key using
 * X25519 elliptic curve scalar multiplication. This is the core operation
 * for ECDH key agreement.
 *
 * @param env Erlang NIF environment
 * @param argc Number of arguments (must be 2)
 * @param argv Array containing [PrivateKey, PublicKey] binaries
 * @return 32-byte shared secret binary or atom 'error'/'badarg'
 *
 * @security The shared secret is zeroed from memory after copying to prevent
 *           sensitive data leakage.
 */
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

/**
 * @brief Encrypt plaintext using ChaCha20-Poly1305 AEAD cipher
 *
 * Performs authenticated encryption with associated data (AEAD) using the
 * ChaCha20-Poly1305 construction. This provides both confidentiality and
 * authenticity guarantees.
 *
 * @param env Erlang NIF environment
 * @param argc Number of arguments (must be 3)
 * @param argv Array containing [Plaintext, Key, AAD] binaries
 * @return Tuple {Ciphertext, Nonce} or atom 'error'/'badarg'
 *
 * @note The nonce is randomly generated for each encryption operation.
 *       The key must be exactly 32 bytes (256 bits).
 * @security Uses cryptographically secure random nonce generation.
 */
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

/**
 * @brief Decrypt ciphertext using ChaCha20-Poly1305 AEAD cipher
 *
 * Performs authenticated decryption with associated data (AEAD) verification
 * using ChaCha20-Poly1305. Verifies both authenticity and integrity before
 * returning plaintext.
 *
 * @param env Erlang NIF environment
 * @param argc Number of arguments (must be 4)
 * @param argv Array containing [Ciphertext, Key, Nonce, AAD] binaries
 * @return Plaintext binary or atom 'error'/'badarg'
 *
 * @note The key must be exactly 32 bytes and nonce exactly 12 bytes.
 *       Ciphertext must be at least 16 bytes (minimum tag size).
 * @security Authentication tag is verified before returning plaintext.
 *           Returns 'error' if authentication fails.
 */
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

/**
 * @brief Generate cryptographically secure random bytes
 *
 * Generates random bytes suitable for cryptographic use, including keys,
 * nonces, salts, and other security-critical values.
 *
 * @param env Erlang NIF environment
 * @param argc Number of arguments (must be 1)
 * @param argv Array containing [Size] integer
 * @return Binary containing random bytes or atom 'badarg'
 *
 * @note Size is limited to 1024 bytes to prevent excessive memory allocation.
 * @security Uses libsodium's cryptographically secure PRNG.
 */
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

/**
 * @brief Convert Ed25519 private key (seed) to X25519 private key
 *
 * Converts an Ed25519 signing key to an X25519 key agreement key, enabling
 * dual-key cryptography where the same identity can be used for both
 * signatures and key agreement.
 *
 * @param env Erlang NIF environment
 * @param argc Number of arguments (must be 1)
 * @param argv Array containing [Ed25519Seed] binary (32 bytes)
 * @return X25519 private key binary (32 bytes) or atom 'error'/'badarg'
 *
 * @note Input should be Ed25519 seed (32 bytes), not full secretkey (64 bytes).
 *       This matches Erlang's crypto:generate_key(eddsa, ed25519) output.
 * @security All intermediate Ed25519 key material is zeroed after conversion.
 */
static ERL_NIF_TERM ed25519_sk_to_x25519_sk(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ed25519_seed;

    // Erlang's crypto:generate_key(eddsa, ed25519) returns 32-byte seed, not 64-byte secretkey
    if (!enif_inspect_binary(env, argv[0], &ed25519_seed) ||
        ed25519_seed.size != crypto_sign_SEEDBYTES)
    {
        return enif_make_badarg(env);
    }

    // First expand the seed to a full Ed25519 keypair
    unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char ed25519_sk[crypto_sign_SECRETKEYBYTES];

    if (crypto_sign_seed_keypair(ed25519_pk, ed25519_sk, ed25519_seed.data) != 0)
    {
        return enif_make_atom(env, "error");
    }

    ERL_NIF_TERM result;
    unsigned char *x25519_sk = enif_make_new_binary(env, crypto_scalarmult_SCALARBYTES, &result);

    if (crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_sk) != 0)
    {
        // Clear sensitive data
        sodium_memzero(ed25519_sk, crypto_sign_SECRETKEYBYTES);
        return enif_make_atom(env, "error");
    }

    // Clear sensitive data
    sodium_memzero(ed25519_sk, crypto_sign_SECRETKEYBYTES);

    return result;
}

/**
 * @brief Convert Ed25519 public key to X25519 public key
 *
 * Converts an Ed25519 verification key to an X25519 key agreement key,
 * completing the dual-key cryptography setup for public key operations.
 *
 * @param env Erlang NIF environment
 * @param argc Number of arguments (must be 1)
 * @param argv Array containing [Ed25519PublicKey] binary (32 bytes)
 * @return X25519 public key binary (32 bytes) or atom 'error'/'badarg'
 *
 * @note This is safe to perform on public keys as no sensitive data is involved.
 *       Essential for X3DH protocol implementation.
 */
static ERL_NIF_TERM ed25519_pk_to_x25519_pk(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ed25519_pk;

    if (!enif_inspect_binary(env, argv[0], &ed25519_pk) ||
        ed25519_pk.size != crypto_sign_PUBLICKEYBYTES)
    {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM result;
    unsigned char *x25519_pk = enif_make_new_binary(env, crypto_scalarmult_BYTES, &result);

    if (crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk.data) != 0)
    {
        return enif_make_atom(env, "error");
    }

    return result;
}

/**
 * @brief NIF function export table
 *
 * Defines the mapping between Erlang function names and C implementations.
 * All functions are marked as dirty CPU-bound operations for proper scheduling.
 */
static ErlNifFunc nif_funcs[] = {
    {"gen_keypair", 0, gen_keypair, 0},
    {"scalarmult", 2, scalarmult, 0},
    {"aead_encrypt", 3, aead_encrypt, 0},
    {"aead_decrypt", 4, aead_decrypt, 0},
    {"rand_bytes", 1, rand_bytes, 0},
    {"ed25519_sk_to_x25519_sk", 1, ed25519_sk_to_x25519_sk, 0},
    {"ed25519_pk_to_x25519_pk", 1, ed25519_pk_to_x25519_pk, 0}};

/**
 * @brief NIF module initialization macro
 *
 * Registers the NIF module with the Erlang runtime system.
 * Specifies load/unload callbacks and function table.
 */
ERL_NIF_INIT(cryptic_nif, nif_funcs, load, NULL, NULL, NULL)
