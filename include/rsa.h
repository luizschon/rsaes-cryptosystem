#ifndef __RSA_H
#define __RSA_H

#include <gmp.h>

typedef struct {
    mpz_t n, e, d;
} rsa_ctx_t;

rsa_ctx_t* rsa_ctx_init();
void rsa_ctx_free(rsa_ctx_t*);

#endif // __RSA_H
