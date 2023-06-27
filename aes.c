#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "aes.h"

#define AES_128_N_RNDS 10
#define AES_128_BLK_LEN_W 4
#define WORD_LEN 4
#define BYTE_LEN 8
#define NIBBLE_LEN 4

/*
 * An attempt at implementing the Advanced Encryption Standard (AES) block chiper according
 * to the FIPS 197 (https://csrc.nist.gov/publications/detail/fips/197/final).
 */

typedef struct { uint32_t words[4]; } aes_block_t;

// Private functions declarations
static void cipher(const aes_block_t* in, aes_block_t* out, const int n_rnds, const uint32_t *rnd_key);
static void key_expansion(const uint8_t* k, uint32_t* w, const int n_rnds);
static void add_round_key(aes_block_t* state, const uint32_t* round_key);
static uint32_t sub_word(uint32_t word);
static uint32_t rot_word(uint32_t word, const int times);
static void sub_bytes(aes_block_t* state);
static void shift_rows(aes_block_t* state);
static void mix_columns(aes_block_t* state);

// Function bodies
void aes_128_gen_key(uint8_t* k) {
#ifndef NDEBUG
  memcpy(k, test_k, AES_128_KEY_LEN);
#else
  for (int i = 0; i < AES_128_KEY_LEN; i++) {
    k[i] = i+1;
  }
#endif
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
  aes_block_t blocks[n_blocks], states[n_blocks];
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
    cipher(&blocks[i], &states[i], AES_128_N_RNDS, expanded_k);
  }
}

void aes_128_decrypt(const uint8_t* c, uint8_t* m, const uint8_t* k) {
  
}

// Private function bodies

static void cipher(const aes_block_t* in, aes_block_t* state, const int n_rnds, const uint32_t* expanded_key) {
  memcpy(state, in, sizeof(aes_block_t));

  add_round_key(state, expanded_key);

  for (size_t i = 1; i < n_rnds; i++) {
    expanded_key += 4;
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, expanded_key);
  }
  
#ifndef NDEBUG
  printf("IN: ");
  for (size_t i = 0; i < AES_128_BLK_LEN_W; i++) {
    printf("0x%08x ", in->words[i]);
  }
  printf("\n\n");
  printf("OUT: ");
  for (size_t i = 0; i < AES_128_BLK_LEN_W; i++) {
    printf("0x%08x ", state->words[i]);
  }
  printf("\n\n");
#endif
}

static void key_expansion(const uint8_t* k, uint32_t* w, const int n_rnds) {
  // Cast key to array of words to facilitate copy
  uint32_t *k_as_words = (uint32_t *) k;
  size_t i = 0;
  const int Nk = AES_128_KEY_LEN/WORD_LEN;

  // The first Nk bytes of the expanded key are the key itself
  for (; i < Nk; i++) {
    w[i] = k_as_words[i];
  }

  for (; i <= 4*n_rnds+3; i++) {
    uint32_t temp = w[i-1];
    
    if (i % Nk == 0) {
      temp = sub_word(rot_word(temp, 1)) ^ Rcon[i/Nk - 1];
    }

    w[i] = w[i-Nk] ^ temp;
  }
  
#ifndef NDEBUG
  printf("Key bytes:\n");
  for (int i = 0; i < AES_128_KEY_LEN; i++)
    printf("0x%02x ", k[i]);
  printf("\n\n");
  printf("Expanded key words:\n");
  for (int i = 0; i < 4*(AES_128_N_RNDS+1); i++)
    printf("0x%08x ", w[i]);
  printf("\n");
#endif
}

static void add_round_key(aes_block_t* state, const uint32_t* round_key) {
  for (size_t i = 0; i < 4; i++) {
    state->words[i] ^= round_key[i];
  }
}

static void sub_bytes(aes_block_t* state) {
  for (size_t i = 0; i < 4; i++) {
    sub_word(&(state->words[i]));
  }
}

static void shift_rows(aes_block_t* state) {
  for (size_t i = 1; i < 4; i++) {
    state->words[i] = rot_word(state->words[i], i);
  }
}

static void mix_columns(aes_block_t* state) {
  // TODO gmul
}

static uint32_t rot_word(uint32_t word, const int times) {
  uint32_t temp;
  
  for (size_t i = 0; i < times; i++) {
      temp = word;
      word = word >> BYTE_LEN;
      word = word | (temp & 0xFF) << (3*BYTE_LEN);
  }
  
#ifndef NDEBUG
  printf("After RotWord %d times: 0x%08x\n", times, word);
#endif

  return word;
}

static uint32_t sub_word(uint32_t word) {
  uint8_t* word_bytes = (uint8_t *) &word;
  uint32_t ret_word = 0;

  for (size_t i = 0; i < WORD_LEN; i++) {
    uint8_t x_nibble = word_bytes[i] >> NIBBLE_LEN,
            y_nibble = word_bytes[i] & 0x0F;
    ret_word |= SBox[x_nibble][y_nibble] << (i*BYTE_LEN); 
  }

#ifndef NDEBUG
  printf("After SubWord: 0x%08x\n", ret_word);
#endif
  
  return ret_word;
}
