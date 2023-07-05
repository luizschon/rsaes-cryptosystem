#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include "rsa.h"

#define MILLER_RABIN_ITERATIONS 10
#define RSA_KEY_SIZE 1024

static void gen_keys(rsa_ctx_t* context);
static void gen_prime(mpz_t prime, size_t num_bits, gmp_randstate_t rand_state);
static bool is_probably_prime(mpz_t n, gmp_randstate_t rand_state);

rsa_ctx_t* rsa_ctx_init() {
  rsa_ctx_t* context = (rsa_ctx_t*) malloc(sizeof(rsa_ctx_t));

  if (context == NULL) {
    fprintf(stderr, "ERROR: couldn't allocate memory for RSA context\n");
  }
  mpz_inits(context->n, context->e, context->d, NULL);
  gen_keys(context);

  return context;
}

void rsa_ctx_free(rsa_ctx_t* context) {
  if (context != NULL) {
    mpz_clears(context->n, context->e, context->d, NULL);
    free(context);
  }
}

static void gen_keys(rsa_ctx_t* context) {
  // Initializes random state outside of the gen_prime function so we don't use the
  // same seed twice be calling the function multiple times in quick succession.
  gmp_randstate_t rand_state;
  gmp_randinit_mt(rand_state);
  gmp_randseed_ui(rand_state, time(NULL));

  // Generates two big prime numbers p, q and computes n and e
  mpz_t p, q;
  mpz_inits(p, q, NULL);
  gen_prime(p, RSA_KEY_SIZE, rand_state);
  gen_prime(q, RSA_KEY_SIZE, rand_state);

  // Computes RSA modulus n
  mpz_mul(context->n, p, q);  // n = pq

  // Chooses biggest exponent e such that 2 < e < φ(n) and gcd(e, φ(n)) = 1, 
  // φ(n) = (p − 1)*(q − 1)
  mpz_t phi_n, gcd;
  mpz_inits(phi_n, gcd, NULL);
  mpz_sub_ui(p, p, 1);  // p = p - 1
  mpz_sub_ui(q, q, 1);  // q = q - 1
  mpz_lcm(phi_n, p, q); // Computes λ(n)

  mpz_sub_ui(context->e, phi_n, 1);  // Initializes exponent with max value (n - 1)
  while (mpz_cmp_ui(context->e, 3) >= 0) {
    mpz_gcd(gcd, context->e, phi_n);
    if (mpz_cmp_ui(gcd, 1) == 1) {
      break;
    }
    mpz_sub_ui(context->e, context->e, 1);
  }

  // Choosing d such that e*d = 1 (mod φ(n))

#ifndef NDEBUG
  gmp_printf("P: %Zd\n\n", p);
  gmp_printf("Q: %Zd\n\n", q);
  gmp_printf("N: %Zd\n\n", context->n);
  gmp_printf("Lambda(n): %Zd\n\n", phi_n);
  gmp_printf("E: %Zd\n\n", context->e);
  gmp_printf("D: %Zd\n\n", context->d);
#endif

  gmp_randclear(rand_state);
  mpz_clears(p, q, phi_n, gcd, NULL);
}

static void gen_prime(mpz_t prime, size_t num_bits, gmp_randstate_t rand_state) {
  // Generate random numbers (mod 2^n - 1) until it passes the primality test.
  do {
    mpz_urandomb(prime, rand_state, num_bits);
    mpz_setbit(prime, num_bits - 1);  // Set (num_bits)th and 1st bit as 1 so the number 
    mpz_setbit(prime, 0);             // is guaranteed to be bigger than 2^(n_bits-1)-1
                                      // and odd.
  } while (!is_probably_prime(prime, rand_state));
}

static bool is_probably_prime(mpz_t n, gmp_randstate_t rand_state) {
  // The 1st bit is set to 1, so there is no need to check if the number is even.
  // But some basic checks againts small primes may prove useful to avoid heavy
  // unnecessary computation.
  // TODO: generate waaay more primes and check if n is divisible by them, maybe
  // store in a pre-computed array; 
  if (mpz_fdiv_ui(n, 3) == 0 || mpz_fdiv_ui(n, 5) == 0 || mpz_fdiv_ui(n, 7) == 0) {
    return false;
  } 

  // Implements the Miller-Rabin probabilistic method of primality checking
  // (https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test).

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
  mpz_t a_to_pow_of_d;
  mpz_init(a_to_pow_of_d);

  for (size_t i = 0; i < MILLER_RABIN_ITERATIONS; i++) {
    bool passed = false;
    // Initializes witness "a" for the compositness of the number "n" with a random value (mod n).
    mpz_urandomm(a_to_pow_of_d, rand_state, n);   // a = random value (mod n)
    mpz_powm(a_to_pow_of_d, a_to_pow_of_d, d, n); // a_to_pow_of_d = a^d

    // First congruency checks: a^d = 1 (mod n) and a^(2^0*d) = -1 (mod n).
    if (mpz_cmp_ui(a_to_pow_of_d, 1) == 0 || mpz_cmp(a_to_pow_of_d, n_minus_one) == 0) {
      continue;
    }

    for (size_t r = 1; r < s; r++) {
      // Subsequent congruency checks: a^(2^r*d) = -1 (mod n), 0 <= r < s.
      mpz_powm_ui(a_to_pow_of_d, a_to_pow_of_d, 2, n);
      if (mpz_cmp(a_to_pow_of_d, n_minus_one) == 0) {
        passed = true;
        break;
      }
    }
    // If witness value "a" failed at every congruency check, then "n" is
    // a composite number.
    if (!passed) {
      mpz_clears(n_minus_one, d, a_to_pow_of_d, NULL);
      return false;
    }
  }
  mpz_clears(n_minus_one, d, a_to_pow_of_d, NULL);
  return true;
}
