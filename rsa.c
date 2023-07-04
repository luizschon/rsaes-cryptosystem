#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include "rsa.h"

#define MILLER_RABIN_ITERATIONS 20

// Global rand state used for the prime generation and primality check
gmp_randstate_t rand_state;

static bool is_probably_prime(mpz_t n);

rsa_ctx_t* rsa_ctx_init() {
    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, time(NULL));

}

static bool is_probably_prime(mpz_t n, gmp_randstate_t rand_state) {
  // The number generated is always odd and bigger then 2^(n_bits-1)-1 since we've set the
  // 0th and (k-1)th bits as 1, so there is no need to check if the number is even.

  // Implements the Miller-Rabin probabilistic method of primality checking
  // (https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)

  // Representing n - 1 = 2^s*d
  mpz_t n_minus_one, d;
  mpz_inits(n_minus_one, d, NULL);
  mpz_sub_ui(n_minus_one, n, 1);
  mpz_set(d, n_minus_one);

  size_t s = 0;
  while (mpz_even_p(d)) {
    mpz_divexact_ui(d, d, 2);
    s++;
  }

  // Miller-Rabin iterations
  for (size_t i = 0; i < MILLER_RABIN_ITERATIONS; i++) {
    bool passed = false;
    // Initializes witness "a" for the compositness of the number "n" with a random value (mod n)
    mpz_t a_to_pow_of_d;
    mpz_inits(a_to_pow_of_d);
    mpz_urandomm(a_to_pow_of_d, rand_state, n);      // a = random value (mod n)
    mpz_powm_ui(a_to_pow_of_d, a_to_pow_of_d, d, n); // a_to_pow_of_d = a^d

    // First congruency checks: a^d = 1 (mod n) and a^(2^0*d) = -1 (mod n)
    if (mpz_cmp_ui(a_to_pow_of_d, 1) == 0 || mpz_cmp_ui(a_to_pow_of_d, n_minus_one) == 0) {
      continue;
    }

    for (size_t r = 1; r < s; r++) {
      // Subsequent congruency checks: a^(2^r*d) = -1 (mod n), 0 <= r < s
      mpz_powm_ui(a_to_pow_of_d, a_to_pow_of_d, 2, n);
      if (mpz_cmp_ui(a_to_pow_of_d, n_minus_one) == 0) {
        passed = true;
        break;
      }
    }
    // If witness value "a" failed at every congruency check, then "n" is
    // a composite number
    if (!passed) {
      mpz_clears(n_minus_one, d, a_to_pow_of_d, NULL);
      return false;
    }
  }
  mpz_clears(n_minus_one, d, NULL);
  return true;
}
