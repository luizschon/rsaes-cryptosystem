#ifndef __RSA_H
#define __RSA_H

#include <gmp.h>
#include "common.h"
 
#define RSA_KEY_SIZE 1024
#define RSA_MOD_LEN 256
#define RSA_PUB_LEN 3
#define SHA256_DIGEST_LEN 32

typedef struct {
    mpz_t *mod, *exp;
} rsa_key_t;

typedef struct {
    mpz_t n, e, d;
    rsa_key_t pub, sec;
} rsa_ctx_t;

typedef struct {
    u8* output;
    size_t len;
} rsa_result_t;

rsa_ctx_t* rsa_ctx_init();
void rsa_ctx_free(rsa_ctx_t*);
void rsa_result_free(rsa_result_t*);
void rsa_export_key(u8*, rsa_key_t);
void rsa_import_key(mpz_t, mpz_t, const u8*);
rsa_result_t* rsa_encrypt(mpz_t, mpz_t, const u8*, size_t);
rsa_result_t* rsa_decrypt(mpz_t, mpz_t, const u8*, size_t);

#endif // __RSA_H
