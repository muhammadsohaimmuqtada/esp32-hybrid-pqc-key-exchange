/*
 * Hybrid PQC Crypto Module Implementation
 * X25519 (mbedTLS) + ML-KEM-512 + HKDF-SHA256 + AES-256-GCM
 *
 * Implements the protocol from Paper Section 3.2:
 * session_key = HKDF-SHA256(X25519_shared_secret || ML-KEM_shared_secret)
 */
#include "crypto_hybrid.h"
#include "mlkem512.h"

#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"

#include "esp_random.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_cpu.h"

#include <string.h>
#include <stdlib.h>

static const char *TAG = "CRYPTO_HYBRID";

/* randombytes implementation using ESP32 hardware RNG */
void randombytes(uint8_t *out, size_t outlen) {
    size_t i;
    for (i = 0; i + 4 <= outlen; i += 4) {
        uint32_t r = esp_random();
        memcpy(out + i, &r, 4);
    }
    if (i < outlen) {
        uint32_t r = esp_random();
        memcpy(out + i, &r, outlen - i);
    }
}

/* Wrapper for mbedTLS RNG signature: int (*f_rng)(void *, unsigned char *, size_t) */
static int mbedtls_rng_wrapper(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    randombytes(buf, len);
    return 0;
}

const char* hybrid_mode_name(handshake_mode_t mode) {
    switch (mode) {
        case MODE_CLASSICAL: return "Classical (X25519)";
        case MODE_PQC:       return "PQC (ML-KEM-512)";
        case MODE_HYBRID:    return "Hybrid (X25519 + ML-KEM-512)";
        default:             return "Unknown";
    }
}

void hybrid_init(hybrid_ctx_t *ctx, handshake_mode_t mode) {
    memset(ctx, 0, sizeof(hybrid_ctx_t));
    ctx->mode = mode;
    ctx->handshake_complete = 0;
}

/*
 * Step 1: Generate ephemeral keypairs
 * X25519: via mbedTLS ECDH
 * ML-KEM-512: via our self-contained implementation
 */
int hybrid_keygen(hybrid_ctx_t *ctx) {
    int ret;

    if (ctx->mode == MODE_CLASSICAL || ctx->mode == MODE_HYBRID) {
        /* Generate X25519 ephemeral keypair */
        mbedtls_ecdh_context ecdh;
        mbedtls_ecdh_init(&ecdh);

        ret = mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_CURVE25519);
        if (ret != 0) {
            ESP_LOGE(TAG, "X25519 setup failed: %d", ret);
            mbedtls_ecdh_free(&ecdh);
            return -1;
        }

        int64_t x25519_start = esp_timer_get_time();
        uint32_t x25519_cycles_start = esp_cpu_get_cycle_count();

        /* Generate keypair - use hardware RNG */
        size_t olen = 0;
        ret = mbedtls_ecdh_make_params(&ecdh, &olen, ctx->x25519_pubkey, sizeof(ctx->x25519_pubkey),
                                        mbedtls_rng_wrapper, NULL);
        if (ret != 0) {
            /* Fallback: generate key material directly */
            randombytes(ctx->x25519_privkey, X25519_KEY_SIZE);
            /* Clamp private key per RFC 7748 */
            ctx->x25519_privkey[0]  &= 248;
            ctx->x25519_privkey[31] &= 127;
            ctx->x25519_privkey[31] |= 64;

            /* Compute public key: pubkey = privkey * basepoint */
            mbedtls_mpi d, qx;
            mbedtls_mpi_init(&d);
            mbedtls_mpi_init(&qx);
            mbedtls_mpi_read_binary_le(&d, ctx->x25519_privkey, X25519_KEY_SIZE);

            mbedtls_ecp_group grp;
            mbedtls_ecp_point Q;
            mbedtls_ecp_group_init(&grp);
            mbedtls_ecp_point_init(&Q);
            mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
            mbedtls_ecp_mul(&grp, &Q, &d, &grp.G,
                           mbedtls_rng_wrapper, NULL);
            mbedtls_mpi_write_binary_le(&Q.MBEDTLS_PRIVATE(X), ctx->x25519_pubkey, X25519_KEY_SIZE);

            mbedtls_mpi_free(&d);
            mbedtls_mpi_free(&qx);
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&Q);
        }

        mbedtls_ecdh_free(&ecdh);
        
        uint32_t x25519_cycles = esp_cpu_get_cycle_count() - x25519_cycles_start;
        int64_t x25519_time = esp_timer_get_time() - x25519_start;
        ESP_LOGI(TAG, "BENCHMARK [X25519 Keygen]: %lld us, %lu cycles", x25519_time, x25519_cycles);
        ESP_LOGI(TAG, "X25519 keypair generated (32-byte pubkey)");
    }

    if (ctx->mode == MODE_PQC || ctx->mode == MODE_HYBRID) {
        int64_t mlkem_start = esp_timer_get_time();
        uint32_t mlkem_cycles_start = esp_cpu_get_cycle_count();

        ret = mlkem512_keypair(ctx->mlkem_pk, ctx->mlkem_sk);
        
        uint32_t mlkem_cycles = esp_cpu_get_cycle_count() - mlkem_cycles_start;
        int64_t mlkem_time = esp_timer_get_time() - mlkem_start;

        if (ret != 0) {
            ESP_LOGE(TAG, "ML-KEM-512 keypair generation failed: %d", ret);
            return -1;
        }
        ESP_LOGI(TAG, "BENCHMARK [ML-KEM-512 Keygen]: %lld us, %lu cycles", mlkem_time, mlkem_cycles);
        ESP_LOGI(TAG, "ML-KEM-512 keypair generated (pk=%d bytes, sk=%d bytes)",
                 KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES);
    }

    return 0;
}

// SANITIZED FOR PUBLIC REPOSITORY
#define DEMO_PSK "REPLACE_WITH_32_BYTE_TEST_PSK_ONLY"
const uint8_t handshake_psk[HANDSHAKE_PSK_SIZE] = DEMO_PSK;

static int compute_hmac_sha256(const uint8_t *key, size_t key_len,
                               const uint8_t *data, size_t data_len,
                               uint8_t *out_mac) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) return -1;
    return mbedtls_md_hmac(md, key, key_len, data, data_len, out_mac);
}

/*
 * Step 2: Pack public keys for transmission to server and sign with HMAC-SHA256
 * Classical: 33B key material + 32B HMAC = 65B
 * PQC:       801B key material + 32B HMAC = 833B
 * Hybrid:    833B key material + 32B HMAC = 865B
 */
int hybrid_pack_pubkeys(hybrid_ctx_t *ctx, uint8_t *buf, size_t buflen) {
    size_t offset = 0;

    /* First byte: mode indicator */
    if (buflen < 1) return -1;
    buf[offset++] = (uint8_t)ctx->mode;

    if (ctx->mode == MODE_CLASSICAL || ctx->mode == MODE_HYBRID) {
        if (offset + X25519_KEY_SIZE > buflen) return -1;
        memcpy(buf + offset, ctx->x25519_pubkey, X25519_KEY_SIZE);
        offset += X25519_KEY_SIZE;
    }

    if (ctx->mode == MODE_PQC || ctx->mode == MODE_HYBRID) {
        if (offset + KYBER_PUBLICKEYBYTES > buflen) return -1;
        memcpy(buf + offset, ctx->mlkem_pk, KYBER_PUBLICKEYBYTES);
        offset += KYBER_PUBLICKEYBYTES;
    }

    /* Compute and append HMAC-SHA256 signature */
    if (offset + 32 > buflen) return -1;
    int ret = compute_hmac_sha256(handshake_psk, HANDSHAKE_PSK_SIZE, buf, offset, buf + offset);
    if (ret != 0) {
        ESP_LOGE(TAG, "HMAC handshake signing failed: %d", ret);
        return -1;
    }
    offset += 32;

    ESP_LOGI(TAG, "Packed %d bytes of public keys (including 32B HMAC) for mode %s",
             (int)offset, hybrid_mode_name(ctx->mode));
    return (int)offset;
}

/*
 * Step 5: Process server response and derive session key
 *
 * Server response format:
 * Classical: [32B X25519 server pub]
 * PQC:       [768B ML-KEM ciphertext]
 * Hybrid:    [32B X25519 server pub][768B ML-KEM ciphertext]
 *
 * Derivation: session_key = HKDF-SHA256(X25519_ss || ML-KEM_ss)
 */
int hybrid_process_server_response(hybrid_ctx_t *ctx,
                                    const uint8_t *server_data,
                                    size_t server_data_len) {
    int ret;
    uint8_t combined_secret[X25519_SECRET_SIZE + KYBER_SSBYTES];
    size_t combined_len = 0;

    if (server_data_len < 16 + 32) {
        ESP_LOGE(TAG, "Server response too short: %d bytes", (int)server_data_len);
        return -1;
    }

    /* Compute and verify HMAC-SHA256 of server response (covers Session ID + crypto payload) */
    uint8_t calculated_hmac[32];
    ret = compute_hmac_sha256(handshake_psk, HANDSHAKE_PSK_SIZE, server_data, server_data_len - 32, calculated_hmac);
    if (ret != 0) {
        ESP_LOGE(TAG, "HMAC verification computation failed: %d", ret);
        return -1;
    }

    int diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= calculated_hmac[i] ^ server_data[server_data_len - 32 + i];
    }
    if (diff != 0) {
        ESP_LOGE(TAG, "Server response HMAC verification failed! Possible MitM attack detected.");
        return -1;
    }
    ESP_LOGI(TAG, "Server response HMAC verification successful!");

    /* First 16 bytes is Session ID (already extracted/skipped on client) */
    size_t offset = 16;

    if (ctx->mode == MODE_CLASSICAL || ctx->mode == MODE_HYBRID) {
        if (offset + X25519_KEY_SIZE > server_data_len - 32) {
            ESP_LOGE(TAG, "Server response too short for X25519 pubkey");
            return -1;
        }

        /* X25519 key agreement */
        const uint8_t *server_x25519_pub = server_data + offset;
        offset += X25519_KEY_SIZE;

        mbedtls_mpi d, qx;
        mbedtls_ecp_group grp;
        mbedtls_ecp_point Q;
        mbedtls_mpi_init(&d);
        mbedtls_mpi_init(&qx);
        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&Q);
        mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
        mbedtls_mpi_read_binary_le(&d, ctx->x25519_privkey, X25519_KEY_SIZE);
        mbedtls_mpi_read_binary_le(&Q.MBEDTLS_PRIVATE(X), server_x25519_pub, X25519_KEY_SIZE);
        mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1);

        mbedtls_mpi shared;
        mbedtls_mpi_init(&shared);

        int64_t x25519_dec_start = esp_timer_get_time();
        uint32_t x25519_dec_cycles_start = esp_cpu_get_cycle_count();
        ret = mbedtls_ecdh_compute_shared(&grp, &shared, &Q, &d,
                                          mbedtls_rng_wrapper, NULL);
        
        uint32_t x25519_dec_cycles = esp_cpu_get_cycle_count() - x25519_dec_cycles_start;
        int64_t x25519_dec_time = esp_timer_get_time() - x25519_dec_start;
        ESP_LOGI(TAG, "BENCHMARK [X25519 Shared Secret]: %lld us, %lu cycles", x25519_dec_time, x25519_dec_cycles);

        if (ret == 0) {
            mbedtls_mpi_write_binary_le(&shared, ctx->x25519_shared_secret, X25519_SECRET_SIZE);
        }

        mbedtls_mpi_free(&d);
        mbedtls_mpi_free(&qx);
        mbedtls_mpi_free(&shared);
        mbedtls_ecp_group_free(&grp);
        mbedtls_ecp_point_free(&Q);

        if (ret != 0) {
            ESP_LOGE(TAG, "X25519 key agreement failed: %d", ret);
            return -1;
        }

        memcpy(combined_secret + combined_len, ctx->x25519_shared_secret, X25519_SECRET_SIZE);
        combined_len += X25519_SECRET_SIZE;
        ESP_LOGI(TAG, "X25519 shared secret derived");
    }

    if (ctx->mode == MODE_PQC || ctx->mode == MODE_HYBRID) {
        if (offset + KYBER_CIPHERTEXTBYTES > server_data_len - 32) {
            ESP_LOGE(TAG, "Server response too short for ML-KEM ciphertext");
            return -1;
        }

        /* ML-KEM-512 decapsulation */
        const uint8_t *server_mlkem_ct = server_data + offset;
        offset += KYBER_CIPHERTEXTBYTES;

        ESP_LOGI(TAG, "[DEBUG] PK sent: %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x%02x%02x%02x%02x",
                 ctx->mlkem_pk[0], ctx->mlkem_pk[1], ctx->mlkem_pk[2], ctx->mlkem_pk[3],
                 ctx->mlkem_pk[4], ctx->mlkem_pk[5], ctx->mlkem_pk[6], ctx->mlkem_pk[7],
                 ctx->mlkem_pk[792], ctx->mlkem_pk[793], ctx->mlkem_pk[794], ctx->mlkem_pk[795],
                 ctx->mlkem_pk[796], ctx->mlkem_pk[797], ctx->mlkem_pk[798], ctx->mlkem_pk[799]);
        
        ESP_LOGI(TAG, "[DEBUG] CT recv: %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x%02x%02x%02x%02x",
                 server_mlkem_ct[0], server_mlkem_ct[1], server_mlkem_ct[2], server_mlkem_ct[3],
                 server_mlkem_ct[4], server_mlkem_ct[5], server_mlkem_ct[6], server_mlkem_ct[7],
                 server_mlkem_ct[760], server_mlkem_ct[761], server_mlkem_ct[762], server_mlkem_ct[763],
                 server_mlkem_ct[764], server_mlkem_ct[765], server_mlkem_ct[766], server_mlkem_ct[767]);

        int64_t mlkem_dec_start = esp_timer_get_time();
        uint32_t mlkem_dec_cycles_start = esp_cpu_get_cycle_count();

        ret = mlkem512_decaps(ctx->mlkem_shared_secret, server_mlkem_ct, ctx->mlkem_sk);
        uint32_t mlkem_dec_cycles = esp_cpu_get_cycle_count() - mlkem_dec_cycles_start;
        int64_t mlkem_dec_time = esp_timer_get_time() - mlkem_dec_start;
        ESP_LOGI(TAG, "BENCHMARK [ML-KEM-512 Decap]: %lld us, %lu cycles", mlkem_dec_time, mlkem_dec_cycles);

        if (ret != 0) {
            ESP_LOGE(TAG, "ML-KEM-512 decapsulation failed: %d", ret);
            return -1;
        }

        memcpy(combined_secret + combined_len, ctx->mlkem_shared_secret, KYBER_SSBYTES);
        combined_len += KYBER_SSBYTES;
        ESP_LOGI(TAG, "ML-KEM-512 shared secret derived and appended");
    }

    /* HKDF-SHA256 key derivation */
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t salt[] = "HybridPQC-ESP32-Session-v1";
    uint8_t info[] = "session-key";

    ret = mbedtls_hkdf(md,
                       salt, sizeof(salt) - 1,
                       combined_secret, combined_len,
                       info, sizeof(info) - 1,
                       ctx->session_key, HKDF_OUTPUT_SIZE);

    /* Zeroize intermediate secrets immediately (Paper Section 4.1) */
    mbedtls_platform_zeroize(combined_secret, sizeof(combined_secret));
    mbedtls_platform_zeroize(ctx->x25519_privkey, sizeof(ctx->x25519_privkey));
    mbedtls_platform_zeroize(ctx->x25519_shared_secret, sizeof(ctx->x25519_shared_secret));
    mbedtls_platform_zeroize(ctx->mlkem_sk, sizeof(ctx->mlkem_sk));
    mbedtls_platform_zeroize(ctx->mlkem_shared_secret, sizeof(ctx->mlkem_shared_secret));

    if (ret != 0) {
        ESP_LOGE(TAG, "HKDF key derivation failed: %d", ret);
        return -1;
    }

    ctx->handshake_complete = 1;
    ESP_LOGI(TAG, "Session key derived via HKDF-SHA256 (mode: %s)", hybrid_mode_name(ctx->mode));

    return 0;
}

/*
 * Step 6: Encrypt telemetry with AES-256-GCM
 * Uses ESP32 hardware AES peripheral for timing-independent operations
 */
int hybrid_encrypt_telemetry(hybrid_ctx_t *ctx,
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *ciphertext, size_t *ct_len) {
    if (!ctx->handshake_complete) {
        ESP_LOGE(TAG, "Cannot encrypt: handshake not complete");
        return -1;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                  ctx->session_key, AES_GCM_KEY_SIZE * 8);
    if (ret != 0) {
        ESP_LOGE(TAG, "AES-GCM setkey failed: %d", ret);
        mbedtls_gcm_free(&gcm);
        return -1;
    }

    /* Generate nonce: [4-byte big-endian counter][8-byte random] */
    uint8_t iv[AES_GCM_IV_SIZE];
    uint32_t count = ctx->telemetry_counter;
    iv[0] = (count >> 24) & 0xFF;
    iv[1] = (count >> 16) & 0xFF;
    iv[2] = (count >> 8) & 0xFF;
    iv[3] = count & 0xFF;
    randombytes(iv + 4, AES_GCM_IV_SIZE - 4);
    ctx->telemetry_counter++;

    /* Output format: [12B IV][ciphertext][16B tag] */
    memcpy(ciphertext, iv, AES_GCM_IV_SIZE);

    uint8_t tag[AES_GCM_TAG_SIZE];
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                     pt_len,
                                     iv, AES_GCM_IV_SIZE,
                                     NULL, 0,  /* no AAD */
                                     plaintext,
                                     ciphertext + AES_GCM_IV_SIZE,
                                     AES_GCM_TAG_SIZE, tag);

    memcpy(ciphertext + AES_GCM_IV_SIZE + pt_len, tag, AES_GCM_TAG_SIZE);
    *ct_len = AES_GCM_IV_SIZE + pt_len + AES_GCM_TAG_SIZE;

    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        ESP_LOGE(TAG, "AES-GCM encrypt failed: %d", ret);
        return -1;
    }

    ESP_LOGI(TAG, "Telemetry encrypted: %d bytes -> %d bytes (AES-256-GCM)",
             (int)pt_len, (int)*ct_len);
    return 0;
}

int hybrid_decrypt_response(hybrid_ctx_t *ctx,
                            const uint8_t *ciphertext, size_t ct_len,
                            uint8_t *plaintext, size_t *pt_len) {
    if (!ctx->handshake_complete) {
        ESP_LOGE(TAG, "Cannot decrypt: handshake not complete");
        return -1;
    }

    if (ct_len < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) {
        ESP_LOGE(TAG, "Ciphertext too short: %d bytes", (int)ct_len);
        return -1;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                  ctx->session_key, AES_GCM_KEY_SIZE * 8);
    if (ret != 0) {
        ESP_LOGE(TAG, "AES-GCM setkey failed: %d", ret);
        mbedtls_gcm_free(&gcm);
        return -1;
    }

    /* Input format: [12B IV][ciphertext][16B tag] */
    const uint8_t *iv = ciphertext;

    /* Verify that the response's counter in GCM IV matches expected sequence counter */
    uint32_t expected_count = ctx->telemetry_counter - 1;
    uint32_t received_count = ((uint32_t)iv[0] << 24) |
                              ((uint32_t)iv[1] << 16) |
                              ((uint32_t)iv[2] << 8)  |
                              (uint32_t)iv[3];
    if (received_count != expected_count) {
        ESP_LOGE(TAG, "Replay check failed: expected response count %u, got %u",
                 (unsigned int)expected_count, (unsigned int)received_count);
        mbedtls_gcm_free(&gcm);
        return -1;
    }

    const uint8_t *actual_ct = ciphertext + AES_GCM_IV_SIZE;
    size_t actual_ct_len = ct_len - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    const uint8_t *tag = ciphertext + AES_GCM_IV_SIZE + actual_ct_len;

    ret = mbedtls_gcm_auth_decrypt(&gcm,
                                   actual_ct_len,
                                   iv, AES_GCM_IV_SIZE,
                                   NULL, 0,  /* no AAD */
                                   tag, AES_GCM_TAG_SIZE,
                                   actual_ct,
                                   plaintext);

    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        ESP_LOGE(TAG, "AES-GCM decrypt failed: %d", ret);
        return -1;
    }

    plaintext[actual_ct_len] = '\0'; // Null-terminate just in case it's a string
    *pt_len = actual_ct_len;

    ESP_LOGI(TAG, "Telemetry response decrypted successfully: %d bytes -> %d bytes",
             (int)ct_len, (int)*pt_len);
    return 0;
}

void hybrid_cleanup(hybrid_ctx_t *ctx) {
    mbedtls_platform_zeroize(ctx, sizeof(hybrid_ctx_t));
    ESP_LOGI(TAG, "All key material zeroized");
}
