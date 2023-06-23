#include <stdio.h>
#include "aes.h"

#define AES_128_N_RNDS 10

/*
 * An attempt at implementing the Advanced Encryption Standard (AES) block chiper according
 * to the FIPS 197 (https://csrc.nist.gov/publications/detail/fips/197/final).
 */

// Local variable declarations
const uint32_t Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

// Private functions declarations
static void cipher(const uint8_t* m, uint8_t* c, const int n_rnds, const uint32_t *rnd_key);
static void key_expansion(const uint8_t* k, uint32_t* w, const int n_rnds);

// Function bodies
void aes_128_gen_key(uint8_t* k) {
  for (int i = 0; i < AES_128_KEY_LEN; i++) {
    k[i] = i+1;
  }
}

void aes_128_encrypt(const uint8_t* m, uint8_t* c, const uint8_t* k) {
  uint32_t expanded_k[4*(AES_128_N_RNDS+1)];
  key_expansion(k, expanded_k, AES_128_N_RNDS);
}

void aes_128_decrypt(const uint8_t* c, uint8_t* m, const uint8_t* k) {
  
}

// Private function bodies
static void key_expansion(const uint8_t* k, uint32_t* w, const int n_rnds) {
  // Cast key to array of words to facilitate copy
  uint32_t *k_as_words = (uint32_t *) k;

  // The first n_rnds words of the expanded key are the key itself
  for (int i = 0; i < n_rnds; i++) {
    w[i] = k_as_words[i];
  }

#ifndef NDEBUG
  printf("Key bytes:\n");
  for (int i = 0; i < AES_128_KEY_LEN; i++)
    printf("0x%02x ", k[i]);
  printf("\n\n");
  printf("Exp key words:\n");
  for (int i = 0; i < AES_128_KEY_LEN/4; i++)
    printf("0x%08x ", w[i]);
  printf("\n");
#endif
}
