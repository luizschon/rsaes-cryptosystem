#include <stdbool.h>
#include <stdio.h>
#include "rsa.h"

static bool is_probably_prime(mpz_t prime, size_t n_iterate);

static bool is_probably_prime(mpz_t num, size_t n_iterate) {
    // The number generated is always odd and bigger then 2^(n_bits-1)-1 since
    // we've set the 0th and (k-1)th bits as 1, so there is no need to check if
    // the number is even.

    // Represents n - 1 = 2^s*d

#ifdef TODO
    for (size_t i = 0; i < n_iterate; i++) {
        //Inicializa as coisas prox a aleatorio
        if (mpz_cmp_ui(a, 1) == 0 || mpz_cmp_ui(a, n_minus_one) == 0) {
            continue;
        }
        for (size_t r = 1; r < s; r++) {
            // y = x * x
            if (mpz_cmp_ui(y, n_minus_one) == 0) {
                goto cnt;
            }
        }
        return false;
        cnt:
    }
    return true;
#endif
}