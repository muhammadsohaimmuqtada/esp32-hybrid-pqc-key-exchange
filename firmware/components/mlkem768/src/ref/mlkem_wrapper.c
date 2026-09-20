/*
 * ML-KEM-768 wrapper — delegates to the reference pq-crystals/kyber implementation
 */
#include "kem.h"
#include "randombytes.h"

/* Our API wraps the reference crypto_kem_* functions */
int mlkem768_keypair(unsigned char *pk, unsigned char *sk) {
    return crypto_kem_keypair(pk, sk);
}

int mlkem768_encaps(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    return crypto_kem_enc(ct, ss, pk);
}

int mlkem768_decaps(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    return crypto_kem_dec(ss, ct, sk);
}
