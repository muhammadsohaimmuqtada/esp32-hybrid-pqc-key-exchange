/*
 * Test: Check verify() within decaps — does re-encryption match?
 * We instrument decaps to see if the ciphertext comparison passes.
 */
#include <stdio.h>
#include <string.h>
#include "mlkem512.h"
#include "fips202.h"

/* Expose internal functions by copying them */
static void gen_matrix_entry(poly *entry, const uint8_t seed[KYBER_SYMBYTES], uint8_t x, uint8_t y) {
    keccak_state state;
    uint8_t extseed[KYBER_SYMBYTES + 2];
    uint8_t buf[SHAKE128_RATE * 2];
    unsigned int ctr = 0, pos = 0, buflen;
    uint16_t val0, val1;
    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES] = x;
    extseed[KYBER_SYMBYTES + 1] = y;
    shake128_absorb_once(&state, extseed, KYBER_SYMBYTES + 2);
    buflen = SHAKE128_RATE * 2;
    shake128_squeeze(buf, buflen, &state);
    while (ctr < KYBER_N) {
        if (pos + 3 > buflen) {
            shake128_squeeze(buf, SHAKE128_RATE, &state);
            buflen = SHAKE128_RATE;
            pos = 0;
        }
        val0 = ((buf[pos]) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
        val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
        pos += 3;
        if (val0 < KYBER_Q && ctr < KYBER_N) entry->coeffs[ctr++] = val0;
        if (val1 < KYBER_Q && ctr < KYBER_N) entry->coeffs[ctr++] = val1;
    }
}

static void indcpa_keypair_test(uint8_t pk[], uint8_t sk[], uint8_t seed_out[64]) {
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvec a[KYBER_K], e, pkpv, skpv;

    randombytes(buf, KYBER_SYMBYTES);
    sha3_512(buf, buf, KYBER_SYMBYTES);
    memcpy(seed_out, buf, 64);  /* Save the seed for debugging */

    for (i = 0; i < KYBER_K; i++)
        for (unsigned int j = 0; j < KYBER_K; j++)
            gen_matrix_entry(&a[i].vec[j], buf, i, j);

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&skpv.vec[i], buf + KYBER_SYMBYTES, nonce++);
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&e.vec[i], buf + KYBER_SYMBYTES, nonce++);

    polyvec_ntt(&skpv);
    polyvec_ntt(&e);

    for (i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }
    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    polyvec_tobytes(sk, &skpv);
    polyvec_tobytes(pk, &pkpv);
    memcpy(pk + KYBER_POLYVECBYTES, buf, KYBER_SYMBYTES);
}

static void indcpa_enc_test(uint8_t c[], const uint8_t m[], const uint8_t pk[], const uint8_t coins[]) {
    unsigned int i;
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[KYBER_K], b;
    poly v, k, epp;
    const uint8_t *seed = pk + KYBER_POLYVECBYTES;

    polyvec_frombytes(&pkpv, pk);

    for (i = 0; i < KYBER_K; i++)
        for (unsigned int j = 0; j < KYBER_K; j++)
            gen_matrix_entry(&at[i].vec[j], seed, j, i);

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&sp.vec[i], coins, nonce++);
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta2(&ep.vec[i], coins, nonce++);
    poly_getnoise_eta2(&epp, coins, nonce++);

    polyvec_ntt(&sp);

    for (i = 0; i < KYBER_K; i++)
        polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
    polyvec_invntt_tomont(&b);
    polyvec_add(&b, &b, &ep);
    polyvec_reduce(&b);

    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);
    poly_invntt_tomont(&v);

    poly_frommsg(&k, m);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    poly_reduce(&v);

    polyvec_compress(c, &b);
    poly_compress(c + KYBER_POLYVECCOMPRESSEDBYTES, &v);
}

static void indcpa_dec_test(uint8_t m[], const uint8_t c[], const uint8_t sk[]) {
    polyvec b, skpv;
    poly v, mp;

    polyvec_decompress(&b, c);
    poly_decompress(&v, c + KYBER_POLYVECCOMPRESSEDBYTES);
    polyvec_frombytes(&skpv, sk);

    polyvec_ntt(&b);
    polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);
    poly_tomsg(m, &mp);
}

int main(void) {
    uint8_t pk[KYBER_PUBLICKEYBYTES];
    uint8_t sk_indcpa[KYBER_INDCPA_SECRETKEYBYTES];
    uint8_t seed[64];

    printf("=== IND-CPA Encrypt/Decrypt Test ===\n");

    /* Generate IND-CPA keys */
    indcpa_keypair_test(pk, sk_indcpa, seed);

    /* Create a message */
    uint8_t msg[32], msg_dec[32];
    randombytes(msg, 32);

    /* Create coins */
    uint8_t coins[32];
    randombytes(coins, 32);

    /* Encrypt */
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    indcpa_enc_test(ct, msg, pk, coins);

    /* Decrypt */
    indcpa_dec_test(msg_dec, ct, sk_indcpa);

    printf("Original msg: ");
    for (int i = 0; i < 32; i++) printf("%02x", msg[i]);
    printf("\n");
    printf("Decrypted   : ");
    for (int i = 0; i < 32; i++) printf("%02x", msg_dec[i]);
    printf("\n");
    printf("Match: %s\n", memcmp(msg, msg_dec, 32) == 0 ? "YES ✓" : "NO ✗");

    /* Now test: encrypt again with same coins, same msg, same pk — does ct match? */
    uint8_t ct2[KYBER_CIPHERTEXTBYTES];
    indcpa_enc_test(ct2, msg, pk, coins);
    printf("\nRe-encrypt match: %s\n", memcmp(ct, ct2, KYBER_CIPHERTEXTBYTES) == 0 ? "YES ✓" : "NO ✗");

    /* Test the full KEM flow */
    printf("\n=== Full KEM Test ===\n");
    uint8_t kem_pk[KYBER_PUBLICKEYBYTES];
    uint8_t kem_sk[KYBER_SECRETKEYBYTES];
    uint8_t kem_ct[KYBER_CIPHERTEXTBYTES];
    uint8_t kem_ss_enc[KYBER_SSBYTES];
    uint8_t kem_ss_dec[KYBER_SSBYTES];

    mlkem512_keypair(kem_pk, kem_sk);
    mlkem512_encaps(kem_ct, kem_ss_enc, kem_pk);
    mlkem512_decaps(kem_ss_dec, kem_ct, kem_sk);

    printf("Encaps SS: ");
    for (int i = 0; i < 32; i++) printf("%02x", kem_ss_enc[i]);
    printf("\nDecaps SS: ");
    for (int i = 0; i < 32; i++) printf("%02x", kem_ss_dec[i]);
    printf("\nMatch: %s\n", memcmp(kem_ss_enc, kem_ss_dec, KYBER_SSBYTES) == 0 ? "YES ✓" : "NO ✗");

    return 0;
}
