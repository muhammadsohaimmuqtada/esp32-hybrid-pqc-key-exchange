#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Inline the Keccak state for direct testing */
#define NROUNDS 24

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

static uint64_t ROL(uint64_t a, int offset) {
    return (a << offset) ^ (a >> (64 - offset));
}

/* Reference Keccak-f[1600] using the standard θ→ρ→π→χ→ι steps */
static void KeccakF1600_Reference(uint64_t state[25]) {
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
        static const int rho_offsets[25] = {
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
        };
        
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                B[y + 5*((2*x + 3*y) % 5)] = ROL(state[x + 5*y], rho_offsets[x + 5*y]);
        
        /* χ step */
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                state[x + 5*y] = B[x + 5*y] ^ ((~B[(x+1)%5 + 5*y]) & B[(x+2)%5 + 5*y]);
        
        /* ι step */
        state[0] ^= KeccakF_RoundConstants[round];
    }
}

int main(void) {
    /* Test: SHA3-256 of empty string
     * SHA3-256 pads with 0x06, then 0x80 at end of rate block
     * Rate = 136 bytes for SHA3-256
     */
    uint64_t state[25];
    memset(state, 0, sizeof(state));
    
    /* Pad: first byte = 0x06, last byte of rate = 0x80 */
    uint8_t *buf = (uint8_t *)state;
    buf[0] ^= 0x06;
    buf[135] ^= 0x80;
    
    KeccakF1600_Reference(state);
    
    /* Extract first 32 bytes as hash */
    uint8_t hash[32];
    memcpy(hash, state, 32);
    
    printf("SHA3-256(\"\") via reference Keccak = ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");
    printf("Expected:                           a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\n");
    
    return 0;
}
