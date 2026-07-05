/*
 * ML-KEM-512 Public API
 * Wraps the reference pq-crystals/kyber implementation
 */
#ifndef MLKEM512_H
#define MLKEM512_H

#include <stdint.h>
#include <stddef.h>

/* Include the reference params.h for size constants */
#include "params.h"

/* KEM API — thin wrappers around crypto_kem_* */
int mlkem512_keypair(uint8_t pk[KYBER_PUBLICKEYBYTES],
                     uint8_t sk[KYBER_SECRETKEYBYTES]);

int mlkem512_encaps(uint8_t ct[KYBER_CIPHERTEXTBYTES],
                    uint8_t ss[KYBER_SSBYTES],
                    const uint8_t pk[KYBER_PUBLICKEYBYTES]);

int mlkem512_decaps(uint8_t ss[KYBER_SSBYTES],
                    const uint8_t ct[KYBER_CIPHERTEXTBYTES],
                    const uint8_t sk[KYBER_SECRETKEYBYTES]);

/* Random bytes interface - implemented per platform */
void randombytes(uint8_t *out, size_t outlen);

#endif /* MLKEM512_H */
