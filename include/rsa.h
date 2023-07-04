#ifndef __RSA_H
#define __RSA_H

#include <gmp.h>

void rsa_gen_pq();
void rsa_sign();
void rsa_verify();

#endif // __RSA_H
