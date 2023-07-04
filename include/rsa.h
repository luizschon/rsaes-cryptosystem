#ifndef __RSA_H
#define __RSA_H

#include <gmp.h>

typedef struct {
    mpz_t p, q;
} rsa_ctx_t;

rsa_ctx_t* rsa_ctx_init();
void rsa_gen_pq();
void rsa_sign();
void rsa_verify();

#endif // __RSA_H
