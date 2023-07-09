#ifndef __RSA_H
#define __RSA_H

#include <gmp.h>
#include "common.h"

typedef struct {
    mpz_t n, e, d;
} rsa_ctx_t;

typedef struct {
    u8* output;
    size_t len;
} rsa_result_t;

rsa_ctx_t* rsa_ctx_init();
void rsa_ctx_free(rsa_ctx_t*);
void rsa_result_free(rsa_result_t*);
rsa_result_t* rsa_encrypt(rsa_ctx_t*, const u8*, size_t);
rsa_result_t* rsa_decrypt(rsa_ctx_t*, const u8*, size_t);

#endif // __RSA_H
