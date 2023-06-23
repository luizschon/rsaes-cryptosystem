#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "aes.h"

#define AES_128_N_RNDS 10
#define AES_128_BLK_LEN_W 4
#define WORD_LEN 4

/*
 * An attempt at implementing the Advanced Encryption Standard (AES) block chiper according
 * to the FIPS 197 (https://csrc.nist.gov/publications/detail/fips/197/final).
 */

typedef struct { uint32_t words[4]; } aes_block_t;

// Local variable declarations
const uint32_t Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

// Private functions declarations
static void cipher(const aes_block_t* in, aes_block_t* out, const int n_rnds, const uint32_t *rnd_key);
static void key_expansion(const uint8_t* k, uint32_t* w, const int n_rnds);
static void add_round_key(uint8_t* state, const uint32_t w);
static void sub_bytes(uint8_t* state);
static void shift_rows(uint8_t* state);
static void mix_columns(uint8_t* state);

// Function bodies
void aes_128_gen_key(uint8_t* k) {
  for (int i = 0; i < AES_128_KEY_LEN; i++) {
    k[i] = i+1;
  }
}

void aes_128_encrypt(const uint8_t* m, uint8_t* c, const size_t msg_len, const uint8_t* k) {
  // Expand key
  uint32_t expanded_k[4*(AES_128_N_RNDS+1)];
  key_expansion(k, expanded_k, AES_128_N_RNDS);

  bool should_add_padded_block = (msg_len % sizeof(aes_block_t) > 0);
  size_t n_blocks = msg_len/sizeof(aes_block_t); // Insert truncaded number of blocks
  n_blocks += should_add_padded_block;           // If m does not fit perfectly in the blocks
                                                 // add another block with padding
  // Initialize blocks
  aes_block_t blocks[n_blocks];
  if (should_add_padded_block) {
    memset(&blocks[n_blocks-1], 0, sizeof(aes_block_t)); // Clear last block (for padding with 0s)
  }
  
  // Insert message bytes into the blocks
  memcpy(blocks, m, msg_len);

#ifndef NDEBUG
  printf("Message: ");
  for (size_t i = 0; i < msg_len; i++) {
    printf("0x%02x ", m[i]);
  }
  printf("\n");
  printf("Blocks (len = %lu):\n", n_blocks);
  printf("[\n");
  for (size_t i = 0; i < n_blocks; i++) {
    printf("  [ ");
    for (size_t j = 0; j < sizeof(blocks)/sizeof(blocks[0]); j++) {
      printf("0x%08x ", blocks[i].words[j]);
    }
    printf("]\n");
  }
  printf("]\n");
#endif

  // Cipher every block
  for (size_t i = 0; i < n_blocks; i++) {
    // cipher(blocks[i], c, AES_128_N_RNDS, expanded_k);
  }
}

void aes_128_decrypt(const uint8_t* c, uint8_t* m, const uint8_t* k) {
  
}

// Private function bodies

static void cipher(const aes_block_t* in, aes_block_t* out, const int n_rnds, const uint32_t* rnd_key) {
  memcpy(out, in, sizeof(aes_block_t));

#ifndef NDEBUG
  printf("IN: ");
  for (size_t i = 0; i < AES_128_BLK_LEN_W; i++) {
    printf("0x%04x ", in->words[i]);
  }
  printf("/n/n");
  printf("OUT: ");
  for (size_t i = 0; i < AES_128_BLK_LEN_W; i++) {
    printf("0x%04x ", out->words[i]);
  }
  printf("/n");
#endif
}

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

