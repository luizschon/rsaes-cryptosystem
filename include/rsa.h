#ifndef __RSA_H
#define __RSA_H

#include <gmp.h>
#include "common.h"

typedef struct {
    mpz_t n, e, d, c;
} rsa_ctx_t;

rsa_ctx_t* rsa_ctx_init();
void rsa_ctx_free(rsa_ctx_t*);
void rsa_oaep_sha256_encrypt(mpz_t, mpz_t, mpz_t, u8*, size_t);
void rsa_oaep_sha256_decrypt(mpz_t, mpz_t, mpz_t, size_t);

#endif // __RSA_H
