/*
 * ML-KEM-512 (FIPS 203) - Complete KEM Implementation
 * IND-CPA scheme + Fujisaki-Okamoto transform
 * Reference: pq-crystals/kyber
 */
#include "mlkem512.h"
#include "fips202.h"
#include <string.h>

/*
 * Matrix generation from seed using SHAKE-128 (rejection sampling)
 */
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

    /* Initial squeeze */
    buflen = SHAKE128_RATE * 2;
    shake128_squeeze(buf, buflen, &state);

    while (ctr < KYBER_N) {
        if (pos + 3 > buflen) {
            /* Need more bytes */
            shake128_squeeze(buf, SHAKE128_RATE, &state);
            buflen = SHAKE128_RATE;
            pos = 0;
        }

        val0 = ((buf[pos] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
        val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q && ctr < KYBER_N)
            entry->coeffs[ctr++] = val0;
        if (val1 < KYBER_Q && ctr < KYBER_N)
            entry->coeffs[ctr++] = val1;
    }
}

/*
 * IND-CPA Key Generation
 */
static void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a[KYBER_K], e, pkpv, skpv;

    /* Generate random seed */
    randombytes(buf, KYBER_SYMBYTES);
    sha3_512(buf, buf, KYBER_SYMBYTES);

    /* Generate matrix A (in NTT domain) */
    for (i = 0; i < KYBER_K; i++) {
        unsigned int j;
        for (j = 0; j < KYBER_K; j++) {
            gen_matrix_entry(&a[i].vec[j], publicseed, i, j);
        }
    }

    /* Generate secret vector s */
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);

    /* Generate error vector e */
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

    /* NTT(s) */
    polyvec_ntt(&skpv);
    polyvec_ntt(&e);

    /* Compute t = A*s + e */
    for (i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }
    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    /* Pack keys */
    polyvec_tobytes(sk, &skpv);
    polyvec_tobytes(pk, &pkpv);
    memcpy(pk + KYBER_POLYVECBYTES, publicseed, KYBER_SYMBYTES);
}

/*
 * IND-CPA Encryption
 */
static void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                       const uint8_t m[KYBER_INDCPA_MSGBYTES],
                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                       const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[KYBER_K], b;
    poly v, k, epp;
    const uint8_t *seed = pk + KYBER_POLYVECBYTES;

    polyvec_frombytes(&pkpv, pk);

    /* Generate matrix A^T */
    for (i = 0; i < KYBER_K; i++) {
        unsigned int j;
        for (j = 0; j < KYBER_K; j++) {
            gen_matrix_entry(&at[i].vec[j], seed, j, i);  /* Transposed */
        }
    }

    /* Sample r, e1, e2 */
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&sp.vec[i], coins, nonce++);
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta2(&ep.vec[i], coins, nonce++);
    poly_getnoise_eta2(&epp, coins, nonce++);

    polyvec_ntt(&sp);

    /* u = A^T * r + e1 */
    for (i = 0; i < KYBER_K; i++)
        polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
    polyvec_invntt_tomont(&b);
    polyvec_add(&b, &b, &ep);
    polyvec_reduce(&b);

    /* v = t^T * r + e2 + msg */
    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);
    poly_invntt_tomont(&v);

    poly_frommsg(&k, m);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    poly_reduce(&v);

    /* Compress and pack ciphertext */
    polyvec_compress(c, &b);
    poly_compress(c + KYBER_POLYVECCOMPRESSEDBYTES, &v);
}

/*
 * IND-CPA Decryption
 */
static void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                       const uint8_t c[KYBER_INDCPA_BYTES],
                       const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
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

/*
 * ML-KEM-512 Key Generation (with FO transform)
 */
int mlkem512_keypair(uint8_t pk[KYBER_PUBLICKEYBYTES],
                     uint8_t sk[KYBER_SECRETKEYBYTES]) {
    indcpa_keypair(pk, sk);
    /* Append pk to sk */
    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
    /* Append H(pk) */
    sha3_256(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    /* Append z (random for implicit rejection) */
    randombytes(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);
    return 0;
}

/*
 * ML-KEM-512 Encapsulation
 * Reference: crypto_kem_enc from pq-crystals/kyber
 */
int mlkem512_encaps(uint8_t ct[KYBER_CIPHERTEXTBYTES],
                    uint8_t ss[KYBER_SSBYTES],
                    const uint8_t pk[KYBER_PUBLICKEYBYTES]) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];

    /* Random message m */
    randombytes(buf, KYBER_SYMBYTES);
    /* H(m) - don't reveal system RNG output */
    sha3_256(buf, buf, KYBER_SYMBYTES);

    /* Multitarget countermeasure: H(pk) */
    sha3_256(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    /* (K, r) = G(m || H(pk)) */
    sha3_512(kr, buf, 2 * KYBER_SYMBYTES);

    /* Encrypt with coins r */
    indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

    /* ss = K (first 32 bytes of kr) — matching reference implementation */
    memcpy(ss, kr, KYBER_SYMBYTES);
    return 0;
}

/*
 * ML-KEM-512 Decapsulation (with implicit rejection)
 * Reference: crypto_kem_dec from pq-crystals/kyber
 */
int mlkem512_decaps(uint8_t ss[KYBER_SSBYTES],
                    const uint8_t ct[KYBER_CIPHERTEXTBYTES],
                    const uint8_t sk[KYBER_SECRETKEYBYTES]) {
    int fail;
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

    /* Decrypt to obtain message m' */
    indcpa_dec(buf, ct, sk);

    /* Multitarget countermeasure: H(pk) from sk */
    memcpy(buf + KYBER_SYMBYTES, sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);

    /* Re-derive (K, r) = G(m' || H(pk)) */
    sha3_512(kr, buf, 2 * KYBER_SYMBYTES);

    /* Re-encrypt and compare */
    indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

    /* Constant-time comparison */
    fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    /* Compute rejection key: rkprf(ss, z, ct) = SHAKE256(z || ct) */
    {
        keccak_state state;
        shake256_init(&state);
        shake256_absorb(&state, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);
        shake256_absorb(&state, ct, KYBER_CIPHERTEXTBYTES);
        shake256_finalize(&state);
        shake256_squeeze(ss, KYBER_SSBYTES, &state);
    }

    /* Copy true key to return buffer if ciphertexts match (!fail) */
    cmov(ss, kr, KYBER_SYMBYTES, (uint8_t)(1 - fail));

    return 0;
}
