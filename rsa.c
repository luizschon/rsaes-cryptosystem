#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <math.h>
#include "rsa.h"
#include "common.h"

#define MILLER_RABIN_ITERATIONS 10
#define RSA_KEY_SIZE 1024
#define RSA_PUBLIC_EXP 65537
#define SHA256_DIGEST_LEN 32
#define MSB_FIRST 1

static void rsa_oaep_sha256_encrypt(const mpz_t, const mpz_t, u8*, const u8*, size_t);
static size_t rsa_oaep_sha256_decrypt(const mpz_t, const mpz_t, u8*, const u8*);
static void oaep_sha256_encode(u8* encoded_msg, const u8* msg, size_t len, size_t n_len);
static size_t oaep_sha256_decode(u8* msg, const u8* encoded_msg, size_t n_len);
static void gen_keys(rsa_ctx_t* context);
static void gen_prime(mpz_t prime, size_t num_bits, gmp_randstate_t rand_state);
static bool is_probably_prime(mpz_t n, gmp_randstate_t rand_state);
static void multiplicative_inverse(mpz_t out, mpz_t in, mpz_t mod);
static void extended_euclidian(mpz_t a, mpz_t b, mpz_t x, mpz_t y);
static void mgf1_sha256(u8* mask, const u8* seed, size_t seed_len, size_t mask_len);
static void invert_bytes(u8* output, const u8* input, size_t len);

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

void rsa_result_free(rsa_result_t* result) {
  if (result != NULL) {
    if (result->output != NULL) {
      free(result->output);
    }
    free(result);
  }
}

rsa_result_t* rsa_encrypt(rsa_ctx_t* context, const u8* msg, size_t len) {
  size_t h_len = SHA256_DIGEST_LEN;
  size_t n_len = sizeof_mpz(context->n);
  rsa_result_t* res = (rsa_result_t*) malloc_or_panic(sizeof(rsa_result_t));

  // Calculates number of blocks that will required to encrypt a message of size "len"
  size_t max_msg_len = n_len - 2*h_len - 2;
  size_t n_blocks = len / max_msg_len;
  bool should_add_partial_block = (len % max_msg_len > 0);
  n_blocks += should_add_partial_block;

  // Allocates memory to store the output in the result struct. Since the result of the RSA-OAEP
  // encryption is always the size in bytes of the RSA modulus, we can pre-compute the number of
  // bytes our output will have based on the number of "blocks" we'll need to form
  res->len = n_blocks * n_len;
  res->output = (u8*) malloc_or_panic(res->len);

  size_t block_idx = 0, msg_idx = 0;

  // Cipher all blocks and save them contiguously in the result output
  for (size_t i = 0; i < n_blocks - 1; i++) {
    rsa_oaep_sha256_encrypt(context->n, context->e, &(res->output[block_idx]), &msg[msg_idx], max_msg_len);
    block_idx += n_len;
    msg_idx += max_msg_len;
  }

  // Cipher last block, whose message could be smaller than the max size of the message
  if (should_add_partial_block) {
    rsa_oaep_sha256_encrypt(context->n, context->e, &(res->output[block_idx]), &msg[msg_idx], len % max_msg_len);
  } else {
    rsa_oaep_sha256_encrypt(context->n, context->e, &(res->output[block_idx]), &msg[msg_idx], max_msg_len);
  }

#ifndef NDEBUG
  printf("Ciphered msg:\n");
  print_bytes(res->output, res->len);
  printf("\n");
#endif

  return res;
}

rsa_result_t* rsa_decrypt(rsa_ctx_t* context, const u8* crypt, size_t len) {
  size_t h_len = SHA256_DIGEST_LEN;
  size_t n_len = sizeof_mpz(context->n);
  rsa_result_t* res = (rsa_result_t*) malloc_or_panic(sizeof(rsa_result_t));

  // Calculates number of blocks that will required to decrypt the cryptogram (should be a multiple
  // of size of RSA modulus in bytes)
  assert(len % n_len == 0);
  size_t n_blocks = len / n_len;

  // Allocates memory to store the output in the result struct with the max possible size, so we don't
  // have to deal with buffer overflows
  res->output = (u8*) malloc_or_panic(n_blocks * (n_len - 2*h_len - 2));
  res->len = 0;

  size_t block_idx = 0, msg_idx = 0;

  // Decipher all blocks and save them contiguously in the result output
  for (size_t i = 0; i < n_blocks; i++) {
    size_t msg_len = rsa_oaep_sha256_decrypt(context->n, context->d, &(res->output[msg_idx]), &crypt[block_idx]);
    block_idx += n_len;
    msg_idx += msg_len;
  }
  // After all blocks have been deciphered, we can be sure the the result length is the sum of the
  // message lengths combined
  res->len = msg_idx;

#ifndef NDEBUG
  printf("Deciphered msg:\n");
  print_bytes(res->output, res->len);
  printf("\n");
#endif

  return res;
}

static void rsa_oaep_sha256_encrypt(const mpz_t mod, const mpz_t exp, u8* crypt, const u8* msg, size_t len) {
  size_t n_len = sizeof_mpz(mod);
  u8 encoded_msg[n_len];
  oaep_sha256_encode(encoded_msg, msg, len, n_len);

  // Interpret encoded message as MSB first, so that the byte 0x00 (locate at idx 0 of the encoded
  // message) can also be the MSB of the integer value, respecting the range set by the RSA
  // encryption (0 <= message representative <= n-1)
  mpz_t message_rep, cryptogram_rep;
  mpz_inits(message_rep, cryptogram_rep, NULL);
  mpz_import(message_rep, sizeof(encoded_msg), MSB_FIRST, sizeof(encoded_msg[0]), 0, 0, encoded_msg);

  // Message representative was to be between 0 and n - 1
  if (mpz_cmp(message_rep, mod) >= 0 || mpz_cmp_ui(message_rep, 0) < 0) {
    fprintf(stderr, "ERROR: message representative out of range\n");
    exit(1);
  }

  mpz_powm(cryptogram_rep, message_rep, exp, mod);
  mpz_export(crypt, NULL, MSB_FIRST, sizeof(crypt[0]), 0, 0, cryptogram_rep);

  mpz_clears(message_rep, cryptogram_rep, NULL);
}

static size_t rsa_oaep_sha256_decrypt(const mpz_t mod, const mpz_t exp, u8* msg, const u8* crypt) {
  size_t n_len = sizeof_mpz(mod);
  size_t hLen = SHA256_DIGEST_LEN;

  // Sanity check
  if (n_len < 2*hLen + 1) {
    fprintf(stderr, "ERROR: rsa decryption error\n");
    exit(1);
  }
  
  // Since our message representative was encrypted by interpreting the encoded OAEP message as MSB
  // first, we need to interpret the cryptogram byte stream as MSB first as well.
  mpz_t cryptogram_rep, message_rep;
  mpz_inits(cryptogram_rep, message_rep, NULL);
  mpz_import(cryptogram_rep, n_len, MSB_FIRST, sizeof(crypt[0]), 0, 0, crypt);

  // Cryptogram representative was to be between 0 and n - 1
  if (mpz_cmp(cryptogram_rep, mod) >= 0 || mpz_cmp_ui(cryptogram_rep, 0) < 0) {
    fprintf(stderr, "ERROR: cryptogram representative out of range\n");
    exit(1);
  }

  // The decryption result of the cryptogram representative results in the message representative of
  // out OAEP encoded message. But recall that the special 0x00 byte is placed in the MSB of the
  // message representative, so we'll need to manually place it int the encoded message array, since
  // zeros to the left are ignored in the GMP library
  mpz_powm(message_rep, cryptogram_rep, exp, mod);

  u8 encoded_msg[n_len];
  encoded_msg[0] = 0x00;  // Place special byte 0x00 of the encoded OAEP message
  mpz_export(encoded_msg + 1, NULL, MSB_FIRST, sizeof(encoded_msg[0]), 0, 0, message_rep);
  mpz_clears(cryptogram_rep, message_rep, NULL);

  return oaep_sha256_decode(msg, encoded_msg, n_len);
}

static void oaep_sha256_encode(u8* encoded_msg, const u8* msg, size_t len, size_t n_len) {
  size_t hLen = SHA256_DIGEST_LEN;
  size_t max_len = n_len - 2*hLen - 2;

  // Check if message is in the correct range
  if (len > max_len) {
    fprintf(stderr, "ERROR: rsa encrypt message too long\n");
    exit(1);
  }

  // Label hash (optional). We'll be using an empty string
  char* label = "";
  u8* lHash;
  sha3_256_wrapper((u8*) label, 0, &lHash);

  // allocate db sized vector
  u8 db[n_len - hLen - 1];
  // set all bytes to 0
  memset(db, 0, sizeof(db));
  // set first 32 bytes to hash of label
  memcpy(db, lHash, hLen);
  // writes 0x01 before last len bytes 
  db[sizeof(db) - (len + 1)] = 0x01;
  // writes msg in last len bytes
  memcpy(&db[sizeof(db) - len], msg, len);
  // result db = lHash || padding 0's || 0x01 || msg

  // OAEP encode procedure:

  u8 seed[hLen];
  gen_rand_bytes(seed, hLen); 

  u8 dbMask[sizeof(db)];
  mgf1_sha256(dbMask, seed, sizeof(seed), sizeof(dbMask));

  u8 maskedDb[sizeof(db)];
  xor_bytes(maskedDb, db, dbMask, sizeof(db));

  u8 seedMask[hLen];
  mgf1_sha256(seedMask, maskedDb, sizeof(maskedDb), hLen);

  u8 maskedSeed[hLen];
  xor_bytes(maskedSeed, seed, seedMask, sizeof(maskedSeed));

  // Forming encoded message: 0x00 || maskedSeed || maskedDB
  encoded_msg[0] = 0x00;
  memcpy(encoded_msg + 1, maskedSeed, sizeof(maskedSeed));
  memcpy(encoded_msg + 1 + sizeof(maskedSeed), maskedDb, sizeof(maskedDb));

  sha3_256_free(lHash);
}

static size_t oaep_sha256_decode(u8* msg, const u8* encoded_msg, size_t n_len) {
  size_t hLen = SHA256_DIGEST_LEN;

  // OAEP decode procedure: 

  u8 maskedSeed[hLen];
  memcpy(maskedSeed, &encoded_msg[1], hLen);
  u8 maskedDb[n_len - hLen - 1];
  memcpy(maskedDb, &encoded_msg[1+hLen], sizeof(maskedDb));

  u8 seedMask[hLen];
  mgf1_sha256(seedMask, maskedDb, sizeof(maskedDb), hLen);

  u8 seed[hLen];
  xor_bytes(seed, maskedSeed, seedMask, sizeof(maskedSeed));

  u8 dbMask[sizeof(maskedDb)];
  mgf1_sha256(dbMask, seed, sizeof(seed), sizeof(dbMask));

  u8 db[sizeof(maskedDb)];
  xor_bytes(db, maskedDb, dbMask, sizeof(maskedDb));

  // Searches for special 0x01 byte inside DB, because we are sure that the message starts after it
  // so we can compute the size of the message
  size_t msg_start = hLen;
  while (msg_start < sizeof(db) && db[msg_start++] != 0x01);

  // Sanity check, makes sure the 0x01 byte was found
  if (msg_start >= sizeof(db)) {
    fprintf(stderr, "ERROR: byte 0x01 not found in DB\n");
    exit(1);
  }

  // Copy message bytes into msg pointer and return its size
  size_t msg_len = sizeof(db) - msg_start;
  memcpy(msg, db + msg_start, msg_len);
  return msg_len;
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
  // To guarantee that p and q are different primes, recomputes q until they are different
  do {
    gen_prime(q, RSA_KEY_SIZE, rand_state);
  } while (mpz_cmp(p, q) == 0);

  // Computes RSA modulus n
  mpz_mul(context->n, p, q);

  // Chooses biggest exponent e such that 2 < e < φ(n) and gcd(e, φ(n)) = 1,  φ(n) = (p − 1)*(q − 1)
  mpz_t phi_n, gcd, p_minus_one, q_minus_one;
  mpz_inits(phi_n, gcd, p_minus_one, q_minus_one, NULL);
  mpz_sub_ui(p_minus_one, p, 1);
  mpz_sub_ui(q_minus_one, q, 1);
  mpz_mul(phi_n, p_minus_one, q_minus_one); // Computes φ(n) = (p - 1)*(q - 1)

  // TODO: this will do, but maybe there's a better way to generate E? This seems to be a very
  // common value used for e (efficient) and other options may be computationally intensive
  mpz_set_ui(context->e, RSA_PUBLIC_EXP);

  // Initializes test value used for basic assertions
  mpz_t test;
  mpz_init(test);

  // Asserts that gcd(e, φ(n)) == 1 and 2 < e < φ(n)
  mpz_gcd(test, context->e, phi_n);
  assert(mpz_cmp_ui(test, 1) == 0);
  assert(mpz_cmp(context->e, phi_n) < 0);
  assert(mpz_cmp_ui(context->e, 2) > 0);

  // Choosing d such that e*d = 1 (mod φ(n)). That is, d is the modular multiplicative inverse of e
  // mod φ(n)
  multiplicative_inverse(context->d, context->e, phi_n);
  
  // Asserts that e*d = 1 (mod φ(n))
  mpz_mul(test, context->e, context->d);
  mpz_mod(test, test, phi_n);
  assert(mpz_cmp_ui(test, 1) == 0);

#ifndef NDEBUG
  gmp_printf("P: %Zd (num bits = %d)\n\n", p, mpz_sizeinbase(p, 2));
  gmp_printf("Q: %Zd (num bits = %d)\n\n", q, mpz_sizeinbase(q, 2));
  gmp_printf("N: %Zd (num bits = %d)\n\n", context->n, mpz_sizeinbase(context->n, 2));
  gmp_printf("E: %Zd\n\n", context->e);
  gmp_printf("D: %Zd (num bits = %d)\n\n", context->d, mpz_sizeinbase(context->d, 2));
#endif

  gmp_randclear(rand_state);
  mpz_clears(p, q, p_minus_one, q_minus_one, phi_n, gcd, test, NULL);
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
  bool res = true;

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
      res = false;
      break;
    }
  }
  mpz_clears(n_minus_one, d, a_to_pow_of_d, NULL);
  return res;
}

static void multiplicative_inverse(mpz_t out, mpz_t in, mpz_t mod) {
  // Uses the Extended Euclidian Algorithm to compute the modular multiplicative inverse of the number
  // "in" mod "mod".
  mpz_t x, y;
  mpz_inits(x, y, NULL);
  extended_euclidian(in, mod, x, y);
  mpz_mod(out, x, mod);
  mpz_clears(x, y, NULL);
}

static void extended_euclidian(mpz_t a, mpz_t b, mpz_t x, mpz_t y) {
  // Recursive implementation of the Extended Euclidian Algorithm.
  // Base case (b == 0)
  if (mpz_cmp_ui(b, 0) == 0) {
    mpz_set_ui(x, 1);
    mpz_set_ui(y, 0);
    return;
  }

  mpz_t x1, y1, mod;
  mpz_inits(x1, y1, mod, NULL);
  mpz_mod(mod, a, b);
  extended_euclidian(b, mod, x1, y1);
  mpz_fdiv_q(y, a, b);  // y = a / b
  mpz_mul(y, y, y1);    // y = y * y1 = (a / b) * y1
  mpz_sub(y, x1, y);    // y = x1 - y = x1 - (a / b) * y1
  mpz_set(x, y1);       // x = y1
  mpz_clears(x1, y1, mod, NULL);
}

static void mgf1_sha256(u8* mask, const u8* seed, size_t seed_len, size_t mask_len) {
  if (mask_len > 0x0100000000) {
    fprintf(stderr, "ERROR: MGF1 mask too long\n");
    exit(1);
  }

  size_t hLen = SHA256_DIGEST_LEN;
  size_t max = ceil((double) mask_len/hLen);
  for (size_t i = 0; i < max; i++) {
    // Converts integer type i to string of octets (bytes) from MSB to LSB
    u8 counter[4];
    invert_bytes(counter, (u8*) &i, sizeof(counter));
    u8* hash, hash_input[seed_len + sizeof(counter)];

    // We need to perform Hash(seed || counter)
    memcpy(hash_input, seed, seed_len);
    memcpy(hash_input + seed_len, &counter, sizeof(counter));
    sha3_256_wrapper(hash_input, sizeof(hash_input), &hash);
    // Now concatenate the result fo the hash into the output mask: mask = mask || Hash(seed || counter)
    memcpy(mask, hash, min(hLen, mask_len - (i*hLen)));
    mask += hLen;
    sha3_256_free(hash);
  }
}

static void invert_bytes(u8* output, const u8* input, size_t len) {
  for (size_t i = 0; i < len; i++) {
    output[i] = input[len - (i+1)];
  }
}
