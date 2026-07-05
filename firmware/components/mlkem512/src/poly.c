/*
 * Polynomial operations for ML-KEM-512
 * Compression, serialization, noise sampling, arithmetic
 */
#include "mlkem512.h"
#include "fips202.h"
#include <string.h>

/*
 * Centered Binomial Distribution sampling
 * Used for noise generation in ML-KEM
 */
static void cbd_eta1(poly *r, const uint8_t buf[3 * KYBER_N / 4]) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < KYBER_N / 4; i++) {
        t  = (uint32_t)buf[3*i]   | ((uint32_t)buf[3*i+1] << 8) | ((uint32_t)buf[3*i+2] << 16);
        d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (j = 0; j < 4; j++) {
            a = (d >> (6*j+0)) & 0x7;
            b = (d >> (6*j+3)) & 0x7;
            r->coeffs[4*i+j] = a - b;
        }
    }
}

static void cbd_eta2(poly *r, const uint8_t buf[KYBER_N / 2]) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < KYBER_N / 8; i++) {
        t  = (uint32_t)buf[4*i]   | ((uint32_t)buf[4*i+1] << 8) |
             ((uint32_t)buf[4*i+2] << 16) | ((uint32_t)buf[4*i+3] << 24);
        d  = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (j = 0; j < 8; j++) {
            a = (d >> (4*j+0)) & 0x3;
            b = (d >> (4*j+2)) & 0x3;
            r->coeffs[8*i+j] = a - b;
        }
    }
}

/* Noise sampling with SHAKE256 PRF */
void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
    uint8_t extseed[KYBER_SYMBYTES + 1];
    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES] = nonce;
    shake256(buf, sizeof(buf), extseed, KYBER_SYMBYTES + 1);
    cbd_eta1(r, buf);
}

void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t buf[KYBER_ETA2 * KYBER_N / 4];
    uint8_t extseed[KYBER_SYMBYTES + 1];
    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES] = nonce;
    shake256(buf, sizeof(buf), extseed, KYBER_SYMBYTES + 1);
    cbd_eta2(r, buf);
}

/* Polynomial serialization */
void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a) {
    unsigned int i;
    uint16_t t0, t1;
    for (i = 0; i < KYBER_N / 2; i++) {
        t0 = a->coeffs[2*i];
        t1 = a->coeffs[2*i+1];
        t0 += ((int16_t)t0 >> 15) & KYBER_Q;
        t1 += ((int16_t)t1 >> 15) & KYBER_Q;
        r[3*i+0] = (uint8_t)(t0 >> 0);
        r[3*i+1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3*i+2] = (uint8_t)(t1 >> 4);
    }
}

void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]) {
    unsigned int i;
    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2*i]   = ((a[3*i+0] >> 0) | ((uint16_t)a[3*i+1] << 8)) & 0xFFF;
        r->coeffs[2*i+1] = ((a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)) & 0xFFF;
    }
}

/* Compress / decompress for ciphertext */
void poly_compress(uint8_t *r, const poly *a) {
    unsigned int i, j;
    int16_t u;
    uint8_t t[8];

    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            u = a->coeffs[8*i+j];
            u += ((int16_t)u >> 15) & KYBER_Q;
            t[j] = ((((uint16_t)u << 4) + KYBER_Q / 2) / KYBER_Q) & 15;
        }
        r[4*i+0] = t[0] | (t[1] << 4);
        r[4*i+1] = t[2] | (t[3] << 4);
        r[4*i+2] = t[4] | (t[5] << 4);
        r[4*i+3] = t[6] | (t[7] << 4);
    }
}

void poly_decompress(poly *r, const uint8_t *a) {
    unsigned int i;
    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2*i+0] = (((uint16_t)(a[i] & 15) * KYBER_Q) + 8) >> 4;
        r->coeffs[2*i+1] = (((uint16_t)(a[i] >> 4) * KYBER_Q) + 8) >> 4;
    }
}

/* Message encoding/decoding */
void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]) {
    unsigned int i, j;
    int16_t mask;
    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            mask = -(int16_t)((msg[i] >> j) & 1);
            r->coeffs[8*i+j] = mask & ((KYBER_Q + 1) / 2);
        }
    }
}

void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a) {
    unsigned int i, j;
    uint32_t t;
    for (i = 0; i < KYBER_N / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t = a->coeffs[8*i+j];
            t += ((int16_t)t >> 15) & KYBER_Q;
            t = (((t << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
            msg[i] |= t << j;
        }
    }
}

/* Polynomial arithmetic */
void poly_ntt(poly *r) { ntt(r->coeffs); }
void poly_invntt_tomont(poly *r) { invntt(r->coeffs); }

void poly_tomont(poly *r) {
    unsigned int i;
    const int16_t f = (1ULL << 32) % KYBER_Q;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * f);
}

void poly_reduce(poly *r) {
    unsigned int i;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

void poly_add(poly *r, const poly *a, const poly *b) {
    unsigned int i;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void poly_sub(poly *r, const poly *a, const poly *b) {
    unsigned int i;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/* Polyvec operations */
void polyvec_compress(uint8_t *r, const polyvec *a) {
    unsigned int i, j, k;
    uint16_t t[4];
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 4; j++) {
            for (k = 0; k < 4; k++) {
                t[k] = a->vec[i].coeffs[4*j+k];
                t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
                t[k] = ((((uint32_t)t[k] << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3ff;
            }
            r[0] = (uint8_t)(t[0] >> 0);
            r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[4] = (uint8_t)(t[3] >> 2);
            r += 5;
        }
    }
}

void polyvec_decompress(polyvec *r, const uint8_t *a) {
    unsigned int i, j, k;
    uint16_t t[4];
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 4; j++) {
            t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
            t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
            t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
            t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
            a += 5;
            for (k = 0; k < 4; k++)
                r->vec[i].coeffs[4*j+k] = ((uint32_t)(t[k] & 0x3FF) * KYBER_Q + 512) >> 10;
        }
    }
}

void polyvec_tobytes(uint8_t *r, const polyvec *a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
}

void polyvec_frombytes(polyvec *r, const uint8_t *a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
}

void polyvec_ntt(polyvec *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_ntt(&r->vec[i]);
}

void polyvec_invntt_tomont(polyvec *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_invntt_tomont(&r->vec[i]);
}

void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b) {
    unsigned int i;
    poly t;
    poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < KYBER_K; i++) {
        poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &t);
    }
    poly_reduce(r);
}

void polyvec_reduce(polyvec *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_reduce(&r->vec[i]);
}

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++)
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}

/* Constant-time comparison */
int verify(const uint8_t *a, const uint8_t *b, size_t len) {
    size_t i;
    uint8_t r = 0;
    for (i = 0; i < len; i++)
        r |= a[i] ^ b[i];
    return (-(uint64_t)r) >> 63;
}

/* Constant-time conditional move */
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    size_t i;
    b = -b;
    for (i = 0; i < len; i++)
        r[i] ^= b & (r[i] ^ x[i]);
}
