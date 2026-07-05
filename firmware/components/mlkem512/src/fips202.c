/*
 * FIPS 202 - SHA-3 / SHAKE Implementation
 * Keccak-f[1600] permutation + sponge construction
 * Portable C for ESP32 Xtensa LX6
 *
 * Reference: NIST FIPS 202, XKCP
 */
#include "fips202.h"
#include <string.h>

#define NROUNDS 24

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Rotation offsets ρ: indexed as [x + 5*y] */
static const int keccak_rho_offsets[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static uint64_t ROL(uint64_t a, int offset) {
    if (offset == 0) return a;
    return (a << offset) | (a >> (64 - offset));
}

/*
 * Keccak-f[1600] permutation — standard θ→ρ→π→χ→ι
 */
static void KeccakF1600_StatePermute(uint64_t state[25]) {
    int round;
    for (round = 0; round < NROUNDS; round++) {
        uint64_t C[5], D[5], B[25];
        int x, y;

        /* θ step */
        for (x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        for (x = 0; x < 5; x++)
            D[x] = C[(x+4)%5] ^ ROL(C[(x+1)%5], 1);
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                state[x + 5*y] ^= D[x];

        /* ρ and π steps */
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                B[y + 5*((2*x + 3*y) % 5)] = ROL(state[x + 5*y], keccak_rho_offsets[x + 5*y]);

        /* χ step */
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                state[x + 5*y] = B[x + 5*y] ^ ((~B[(x+1)%5 + 5*y]) & B[(x+2)%5 + 5*y]);

        /* ι step */
        state[0] ^= KeccakF_RoundConstants[round];
    }
}

/*
 * Sponge absorb/squeeze helpers
 */
static void keccak_init(keccak_state *state) {
    memset(state->s, 0, sizeof(state->s));
    state->pos = 0;
}

static void keccak_absorb(keccak_state *state, unsigned int r, const uint8_t *in, size_t inlen) {
    uint8_t *buf = (uint8_t *)state->s;
    unsigned int pos = state->pos;

    while (inlen > 0) {
        size_t chunk = r - pos;
        if (chunk > inlen) chunk = inlen;
        for (size_t i = 0; i < chunk; i++)
            buf[pos + i] ^= in[i];
        pos += chunk;
        in += chunk;
        inlen -= chunk;
        if (pos == r) {
            KeccakF1600_StatePermute(state->s);
            pos = 0;
        }
    }
    state->pos = pos;
}

static void keccak_finalize(keccak_state *state, unsigned int r, uint8_t p) {
    uint8_t *buf = (uint8_t *)state->s;
    buf[state->pos] ^= p;
    buf[r - 1] ^= 0x80;
    KeccakF1600_StatePermute(state->s);
    state->pos = 0;
}

static void keccak_squeeze(uint8_t *out, size_t outlen, keccak_state *state, unsigned int r) {
    uint8_t *buf = (uint8_t *)state->s;
    unsigned int pos = state->pos;

    while (outlen > 0) {
        if (pos == r) {
            KeccakF1600_StatePermute(state->s);
            pos = 0;
        }
        size_t chunk = r - pos;
        if (chunk > outlen) chunk = outlen;
        memcpy(out, buf + pos, chunk);
        out += chunk;
        outlen -= chunk;
        pos += chunk;
    }
    state->pos = pos;
}

static void keccak_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state, unsigned int r) {
    while (nblocks > 0) {
        KeccakF1600_StatePermute(state->s);
        memcpy(out, state->s, r);
        out += r;
        nblocks--;
    }
}

/*
 * SHAKE-128
 */
void shake128_init(keccak_state *state) { keccak_init(state); }
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen) { keccak_absorb(state, SHAKE128_RATE, in, inlen); }
void shake128_finalize(keccak_state *state) { keccak_finalize(state, SHAKE128_RATE, 0x1F); }
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state) { keccak_squeeze(out, outlen, state, SHAKE128_RATE); }
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state) { keccak_squeezeblocks(out, nblocks, state, SHAKE128_RATE); }

void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen) {
    keccak_init(state);
    keccak_absorb(state, SHAKE128_RATE, in, inlen);
    keccak_finalize(state, SHAKE128_RATE, 0x1F);
}

/*
 * SHAKE-256
 */
void shake256_init(keccak_state *state) { keccak_init(state); }
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen) { keccak_absorb(state, SHAKE256_RATE, in, inlen); }
void shake256_finalize(keccak_state *state) { keccak_finalize(state, SHAKE256_RATE, 0x1F); }
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state) { keccak_squeeze(out, outlen, state, SHAKE256_RATE); }
void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state) { keccak_squeezeblocks(out, nblocks, state, SHAKE256_RATE); }

void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen) {
    keccak_init(state);
    keccak_absorb(state, SHAKE256_RATE, in, inlen);
    keccak_finalize(state, SHAKE256_RATE, 0x1F);
}

void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    keccak_state state;
    shake256_absorb_once(&state, in, inlen);
    keccak_squeeze(out, outlen, &state, SHAKE256_RATE);
}

/*
 * SHA3-256
 */
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen) {
    keccak_state state;
    keccak_init(&state);
    keccak_absorb(&state, SHA3_256_RATE, in, inlen);
    keccak_finalize(&state, SHA3_256_RATE, 0x06);
    keccak_squeeze(h, 32, &state, SHA3_256_RATE);
}

/*
 * SHA3-512
 */
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen) {
    keccak_state state;
    keccak_init(&state);
    keccak_absorb(&state, SHA3_512_RATE, in, inlen);
    keccak_finalize(&state, SHA3_512_RATE, 0x06);
    keccak_squeeze(h, 64, &state, SHA3_512_RATE);
}
