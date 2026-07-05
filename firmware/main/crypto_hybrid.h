/*
 * Hybrid PQC Crypto Module for ESP32
 * X25519 (mbedTLS) + ML-KEM-512 + HKDF-SHA256
 * Paper Section 3.2 Protocol Implementation
 */
#ifndef CRYPTO_HYBRID_H
#define CRYPTO_HYBRID_H

#include <stdint.h>
#include <stddef.h>
#include "mlkem512.h"

/* Handshake modes for benchmarking */
typedef enum {
    MODE_CLASSICAL = 0,   /* X25519 only */
    MODE_PQC       = 1,   /* ML-KEM-512 only */
    MODE_HYBRID    = 2    /* X25519 + ML-KEM-512 */
} handshake_mode_t;

/* Key material sizes */
#define X25519_KEY_SIZE     32
#define X25519_SECRET_SIZE  32
#define HKDF_OUTPUT_SIZE    32
#define AES_GCM_KEY_SIZE    32
#define AES_GCM_IV_SIZE     12
#define AES_GCM_TAG_SIZE    16
#define HANDSHAKE_PSK_SIZE  32

extern const uint8_t handshake_psk[HANDSHAKE_PSK_SIZE];

/* Client handshake state */
typedef struct {
    /* X25519 */
    uint8_t x25519_privkey[X25519_KEY_SIZE];
    uint8_t x25519_pubkey[X25519_KEY_SIZE];
    uint8_t x25519_shared_secret[X25519_SECRET_SIZE];

    /* ML-KEM-512 */
    uint8_t mlkem_pk[KYBER_PUBLICKEYBYTES];
    uint8_t mlkem_sk[KYBER_SECRETKEYBYTES];
    uint8_t mlkem_shared_secret[KYBER_SSBYTES];

    /* Derived session key */
    uint8_t session_key[HKDF_OUTPUT_SIZE];

    /* Mode */
    handshake_mode_t mode;
    int handshake_complete;
    uint32_t telemetry_counter;  /* Monotonic sequence counter for replay protection */
} hybrid_ctx_t;

/* Initialize the hybrid context */
void hybrid_init(hybrid_ctx_t *ctx, handshake_mode_t mode);

/* Step 1: Generate ephemeral keypairs */
int hybrid_keygen(hybrid_ctx_t *ctx);

/* Step 2: Serialize public keys for transmission (returns bytes written) */
int hybrid_pack_pubkeys(hybrid_ctx_t *ctx, uint8_t *buf, size_t buflen);

/* Step 5: Process server response and derive session key */
int hybrid_process_server_response(hybrid_ctx_t *ctx,
                                    const uint8_t *server_data,
                                    size_t server_data_len);

/* Step 6: Encrypt telemetry with AES-256-GCM */
int hybrid_encrypt_telemetry(hybrid_ctx_t *ctx,
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *ciphertext, size_t *ct_len);

/* Step 7: Decrypt server response with AES-256-GCM */
int hybrid_decrypt_response(hybrid_ctx_t *ctx,
                             const uint8_t *ciphertext, size_t ct_len,
                             uint8_t *plaintext, size_t *pt_len);

/* Cleanup: zeroize all secrets */
void hybrid_cleanup(hybrid_ctx_t *ctx);

/* Get mode name string */
const char* hybrid_mode_name(handshake_mode_t mode);

#endif /* CRYPTO_HYBRID_H */
