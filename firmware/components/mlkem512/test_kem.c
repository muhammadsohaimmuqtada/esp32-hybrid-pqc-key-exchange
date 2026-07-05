/*
 * Test program for ML-KEM-512 correctness
 * Compile: gcc -O2 -I include -o test_kem test_kem.c src/kem.c src/ntt.c src/poly.c src/fips202.c randombytes.c
 */
#include <stdio.h>
#include <string.h>
#include "mlkem512.h"

int main(void) {
    uint8_t pk[KYBER_PUBLICKEYBYTES];
    uint8_t sk[KYBER_SECRETKEYBYTES];
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    uint8_t ss_enc[KYBER_SSBYTES];
    uint8_t ss_dec[KYBER_SSBYTES];

    int pass = 0, fail = 0;

    for (int i = 0; i < 20; i++) {
        mlkem512_keypair(pk, sk);
        mlkem512_encaps(ct, ss_enc, pk);
        mlkem512_decaps(ss_dec, ct, sk);

        int match = (memcmp(ss_enc, ss_dec, KYBER_SSBYTES) == 0);
        if (match) pass++; else fail++;

        printf("Round %2d: enc=", i);
        for (int j = 0; j < 8; j++) printf("%02x", ss_enc[j]);
        printf("  dec=");
        for (int j = 0; j < 8; j++) printf("%02x", ss_dec[j]);
        printf("  %s\n", match ? "PASS" : "FAIL");
    }

    printf("\nResult: %d/%d passed\n", pass, pass + fail);
    return (fail > 0) ? 1 : 0;
}
