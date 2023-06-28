#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "aes.h"

#define AES_128_N_RNDS 10
#define AES_128_BLK_LEN_W 4
#define AES_128_EXPKEY_LEN 4
#define WORD_LEN 4
#define BYTE_LEN 8
#define NIBBLE_LEN 4

/*
 * An attempt at implementing the Advanced Encryption Standard (AES) block chiper according
 * to the FIPS 197 (https://csrc.nist.gov/publications/detail/fips/197/final).
 */

const u32 Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

const u8 SBox[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

const u8 InvSbox[16][16] = {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

#ifndef NDEBUG
const u8 test_k[AES_128_KEY_LEN] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
#endif

// Private functions declarations
static void cipher(aes_state_t* state, const int n_rnds, u32* expanded_key);
static void key_expansion(const u8* k, u32* w, const int n_rnds);
static void add_round_key(aes_state_t* state, const uint32_t* round_key);
static u32 sub_word(u32 word);
static u32 inv_sub_word(u32 word);
static u32 rot_word(u32 word, const int times);
static void sub_bytes(aes_state_t* state);
static void shift_rows(aes_state_t* state);
static void mix_columns(aes_state_t* state);
static void inv_shift_rows(aes_state_t* state);
static u8 gmul(u8 a, u8 b);

#ifndef NDEBUG
static void print_state(const aes_state_t* state);
static void print_bytes(const u8* bytes, const size_t len);
static void print_words(const u32* words, const size_t len);
#endif

// Function bodies
void aes_128_gen_key(u8* k) {
#ifndef NDEBUG
  memcpy(k, test_k, AES_128_KEY_LEN);
#else
  for (int i = 0; i < AES_128_KEY_LEN; i++) {
    k[i] = i+1;
  }
#endif
}

aes_ctx_t* aes_128_ctx_init(aes_key_t key, u8* msg, size_t len) {
  aes_ctx_t* context = (aes_ctx_t*) malloc(sizeof(aes_ctx_t));

  if (context == NULL) {
    printf("DEU RUIM\n");
    return NULL;
  }

  key_expansion(key, context->expanded_key, AES_128_N_RNDS);
  
  bool should_add_padded_block = (len % sizeof(aes_state_t) > 0);
  size_t n_states = len/sizeof(aes_state_t); // Insert truncaded number of blocks
  n_states += should_add_padded_block;       // If m does not fit perfectly in the blocks
                                             // add another block with padding
  // Initialize blocks
  aes_state_t* states = (aes_state_t*) malloc(n_states * sizeof(aes_state_t));

  if (should_add_padded_block) {
    memset(&states[n_states-1], 0, sizeof(aes_state_t)); // Clear last block (for padding with 0s)
  }
  
  // Insert message bytes into state blocks
  size_t m_idx = 0;
  for (size_t b = 0; b < n_states; b++) {
    for (size_t i = 0; i < 4; i++) {
      for (size_t j = 0; j < 4; j++) {
        states[b].bytes[j][i] = msg[m_idx++];
      }
    }
  }

  context->n_states = n_states;
  context->states = states;
  
#ifndef NDEBUG
  printf("Message: \n");
  print_bytes(msg, len);
  printf("\n");
  printf("Blocks as bytes (len = %lu):\n", n_states);
  for (size_t b = 0; b < n_states; b++) {
    print_state(&states[b]);
    printf("\n");
  }
  printf("END OF BLOCKS\n\n");
#endif 

  return context;
}

void aes_128_ctx_free(aes_ctx_t* context) {
  if (context != NULL) {
    free(context->states);
    free(context);
  }
}

void aes_128_encrypt(aes_ctx_t* context) {
  // Cipher every block
  for (size_t i = 0; i < context->n_states; i++) {
    cipher(&(context->states[i]), AES_128_N_RNDS, context->expanded_key);
  }

}

void aes_128_decrypt(aes_ctx_t* context) {
  
}

// Private function bodies

static void cipher(aes_state_t* state, const int n_rnds, u32* expanded_key) {
  add_round_key(state, expanded_key);

  for (size_t i = 1; i < n_rnds; i++) {
    expanded_key += 4;
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, expanded_key);
  }
  expanded_key += 4;
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, expanded_key);
  
#ifndef NDEBUG
  printf("RES:\n");
  print_state(state);
  printf("\n");
#endif
}

static void key_expansion(const u8* k, u32* w, const int n_rnds) {
  // Cast key to array of words to facilitate copy
  u32 *k_as_words = (u32 *) k;
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
  print_bytes(k, AES_128_KEY_LEN);
  printf("\n");
  printf("Expanded key words:\n");
  print_words(w, 4*(AES_128_N_RNDS+1));
  printf("\n");
#endif
}

static void add_round_key(aes_state_t* state, const u32* round_key) {
  u8* round_key_bytes = (u8*) round_key;
  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < 4; j++) {
      state->bytes[j][i] ^= round_key_bytes[i*4 + j];
    }
  }

#ifndef NDEBUG
  printf("Round key value:\n");
  print_state(round_key);
  printf("\n");
#endif
}

static void sub_bytes(aes_state_t* state) {
  for (size_t i = 0; i < 4; i++) {
    state->words[i] = sub_word(state->words[i]);
  }

#ifndef NDEBUG
  printf("After sub bytes:\n");
  print_state(state);
  printf("\n");
#endif
}

static void shift_rows(aes_state_t* state) {
  for (size_t i = 1; i < 4; i++) {
    state->words[i] = rot_word(state->words[i], i);
  }

#ifndef NDEBUG
  printf("After shift rows:\n");
  print_state(state);
  printf("\n");
#endif
}

static void inv_shift_rows(aes_state_t* state) {
  for (size_t i = 1; i < 4; i++) {
    state->words[i] = rot_word(state->words[i], i);
  }

#ifndef NDEBUG
  printf("After shift rows:\n");
  print_state(state);
  printf("\n");
#endif
}

static void mix_columns(aes_state_t* state) {
  u8 column[4];
  // Copy original state because it will be modified
  aes_state_t original_state;
  memcpy(&original_state, state, sizeof(aes_state_t));

  for (size_t j = 0; j < 4; j++) {
    for (size_t i = 0; i < 4; i++) {
      column[i] = original_state.bytes[i][j];
    }
    state->bytes[0][j] = gmul(0x02, column[0]) ^ gmul(0x03, column[1]) ^ column[2] ^ column[3];
    state->bytes[1][j] = column[0] ^ gmul(0x02, column[1]) ^ gmul(0x03, column[2]) ^ column[3];
    state->bytes[2][j] = column[0] ^ column[1] ^ gmul(0x02, column[2]) ^ gmul(0x03, column[3]);
    state->bytes[3][j] = gmul(0x03, column[0]) ^ column[1] ^ column[2] ^ gmul(0x02, column[3]);
  }

#ifndef NDEBUG
  printf("After mix columns:\n");
  print_state(state);
  printf("\n");
#endif
}

static u32 rot_word(u32 word, const int times) {
  u32 temp;

  for (size_t i = 0; i < times; i++) {
      temp = word;
      word = word >> BYTE_LEN;
      word = word | (temp & 0xFF) << (3*BYTE_LEN);
  }
  
#ifndef NDEBUG
  printf("After rot word %d times: %08x\n", times, word);
#endif

  return word;
}

static u32 inv_rot_word(u32 word, const int times) {
  u32 temp;

  for (size_t i = 0; i < times; i++) {
      temp = word;
      word = word << BYTE_LEN;
      word = word | (temp & 0xFF) >> (3*BYTE_LEN);
  }
  
#ifndef NDEBUG
  printf("After rot word %d times: %08x\n", times, word);
#endif

  return word;
}

static u32 sub_word(u32 word) {
  u8* word_bytes = (u8 *) &word;
  u32 ret_word = 0;

  for (size_t i = 0; i < WORD_LEN; i++) {
    uint8_t x_nibble = word_bytes[i] >> NIBBLE_LEN,
            y_nibble = word_bytes[i] & 0x0F;
    ret_word |= SBox[x_nibble][y_nibble] << (i*BYTE_LEN); 
  }

#ifndef NDEBUG
  printf("After sub word: %08x\n", ret_word);
#endif
  
  return ret_word;
}

static u32 inv_sub_word(u32 word) {
  u8* word_bytes = (u8 *) &word;
  u32 ret_word = 0;

  for (size_t i = 0; i < WORD_LEN; i++) {
    uint8_t x_nibble = word_bytes[i] >> NIBBLE_LEN,
            y_nibble = word_bytes[i] & 0x0F;
    ret_word |= InvSbox[x_nibble][y_nibble] << (i*BYTE_LEN); 
  }

#ifndef NDEBUG
  printf("After sub word: %08x\n", ret_word);
#endif
  
  return ret_word;
}

static u8 gmul(u8 a, u8 b) {
  u8 res = 0;

  // Iterate over the bits that compose b aplying the repeated xTimes() technique, see
  // equation 4.6 in the reference
  while (b) {
    if (b & 0x01) {
      res ^= a;
    }
    // xTimes() definition , see equation 4.5 of the reference
    if (a & 0x80) {
      a = (a << 1) ^ 0x1B;
    } else {
      a = a << 1;
    }
    b = b >> 1;
  }

  return res;
}

#ifndef NDEBUG
static void print_state(const aes_state_t* state) {
  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < 4; j++) {
      printf("%02x ", state->bytes[i][j]);
    }  
    printf("\n");
  }  
}

static void print_bytes(const u8* bytes, const size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x ", bytes[i]);
  }
  printf("\n");
}
 
static void print_words(const u32* words, const size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%08x ", words[i]);
  }
  printf("\n");
}
#endif
