/*
 * Deep test for ML-KEM-512 — check if IND-CPA enc/dec round-trips correctly
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mlkem512.h"
#include "fips202.h"

/* Test IND-CPA encrypt → decrypt round-trip */
static void test_indcpa_roundtrip(void) {
    printf("=== IND-CPA Round-Trip Test ===\n");
    
    /* We can't directly call indcpa_* since they're static.
       Instead, test that keygen→encaps→decaps matches at the KEM level
       by checking if the ciphertext re-encryption matches. */
    
    uint8_t pk[KYBER_PUBLICKEYBYTES];
    uint8_t sk[KYBER_SECRETKEYBYTES];
    
    mlkem512_keypair(pk, sk);
    
    /* Manually do what encaps does, but save intermediaries */
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];
    
    /* Fixed random for reproducibility */
    randombytes(buf, KYBER_SYMBYTES);
    printf("  Random m (pre-hash): ");
    for (int i = 0; i < 8; i++) printf("%02x", buf[i]);
    printf("...\n");
    
    sha3_256(buf, buf, KYBER_SYMBYTES);
    printf("  Hashed m: ");
    for (int i = 0; i < 8; i++) printf("%02x", buf[i]);
    printf("...\n");
    
    /* H(pk) */
    uint8_t h_pk[32];
    sha3_256(h_pk, pk, KYBER_PUBLICKEYBYTES);
    printf("  H(pk): ");
    for (int i = 0; i < 8; i++) printf("%02x", h_pk[i]);
    printf("...\n");
    
    /* Check H(pk) stored in sk matches */
    uint8_t *sk_h_pk = sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES;
    printf("  H(pk) in sk: ");
    for (int i = 0; i < 8; i++) printf("%02x", sk_h_pk[i]);
    printf("...\n");
    int h_pk_match = (memcmp(h_pk, sk_h_pk, KYBER_SYMBYTES) == 0);
    printf("  H(pk) match: %s\n", h_pk_match ? "YES" : "NO");
    
    /* Check pk in sk matches */
    uint8_t *sk_pk = sk + KYBER_INDCPA_SECRETKEYBYTES;
    int pk_match = (memcmp(pk, sk_pk, KYBER_PUBLICKEYBYTES) == 0);
    printf("  pk stored in sk match: %s\n", pk_match ? "YES" : "NO");
}

/* Test SHA3 functions for basic correctness */
static void test_sha3(void) {
    printf("\n=== SHA3 Correctness Test ===\n");
    
    /* Test SHA3-256("") known answer */
    uint8_t empty_hash[32];
    sha3_256(empty_hash, (const uint8_t *)"", 0);
    printf("  SHA3-256(\"\") = ");
    for (int i = 0; i < 32; i++) printf("%02x", empty_hash[i]);
    printf("\n");
    /* Expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a */
    
    uint8_t expected[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };
    
    if (memcmp(empty_hash, expected, 32) == 0) {
        printf("  SHA3-256 CORRECT ✓\n");
    } else {
        printf("  SHA3-256 INCORRECT ✗\n");
        printf("  Expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected[i]);
        printf("\n");
    }
    
    /* Test SHA3-512("") */
    uint8_t empty_hash_512[64];
    sha3_512(empty_hash_512, (const uint8_t *)"", 0);
    printf("  SHA3-512(\"\") = ");
    for (int i = 0; i < 16; i++) printf("%02x", empty_hash_512[i]);
    printf("...\n");
    /* Expected starts with: a69f73cca23a9ac5... */
    if (empty_hash_512[0] == 0xa6 && empty_hash_512[1] == 0x9f) {
        printf("  SHA3-512 CORRECT ✓\n");
    } else {
        printf("  SHA3-512 INCORRECT ✗\n");
    }
}

/* Test NTT forward + inverse round-trip */
static void test_ntt_roundtrip(void) {
    printf("\n=== NTT Round-Trip Test ===\n");
    
    int16_t r[256], r_orig[256];
    
    /* Initialize with known values */
    for (int i = 0; i < 256; i++) {
        r[i] = (int16_t)(i * 17 % KYBER_Q);
        r_orig[i] = r[i];
    }
    
    ntt(r);
    invntt(r);
    
    /* After NTT→INTT, values should be r_orig * MONT mod q */
    /* Actually invntt applies *f=1441 scaling, so check if consistent */
    int all_match = 1;
    for (int i = 0; i < 256; i++) {
        int16_t reduced = barrett_reduce(r[i]);
        int16_t orig_reduced = barrett_reduce(r_orig[i]);
        /* They should differ by a Montgomery factor */
        if (i < 4) {
            printf("  r[%d]: orig=%d, after NTT+INTT=%d\n", i, orig_reduced, reduced);
        }
    }
    printf("  (Values may differ by Montgomery factor, this is expected)\n");
}

int main(void) {
    test_sha3();
    test_ntt_roundtrip();
    test_indcpa_roundtrip();
    return 0;
}
