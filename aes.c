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
 * A completely compiler and architecture-dependent attempt at implementing the Advanced Encryption
 * Standard (AES) block chiper according to the FIPS 197 (https://csrc.nist.gov/publications/detail/fips/197/final)
 * using CTR-mode block encryption (https://www.rfc-editor.org/info/rfc3686)
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
const u8 test_k[AES_128_KEY_LEN] = { 0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8, 0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC };
const u8 iv[8] = { 0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0 };
const u8 nonce[4] = { 0x00, 0xE0, 0x01, 0x7B };
#endif

// Private functions declarations
static void init_counter_block(aes_block_t* counter_block, aes_ctx_t* context);
static void cipher(aes_block_t* state, const int n_rnds, u32* expanded_key);
static void key_expansion(const u8* k, u32* w, const int n_rnds);
static void add_round_key(aes_block_t* state, const uint32_t* round_key);
static u32 sub_word(u32 word);
static u32 inv_sub_word(u32 word);
static u32 rot_word(u32 word, const int times);
static void sub_bytes(aes_block_t* state);
static void shift_rows(aes_block_t* state);
static void inv_shift_rows(aes_block_t* state);
static void mix_columns(aes_block_t* state);
static void increment_counter(aes_block_t* counter_block);
static u8 gmul(u8 a, u8 b);
static void xor_block_into_bytes(u8* bytes, const aes_block_t* state);
static void xor_bytes_into_block(aes_block_t* state, const u8* bytes);
static void gen_rand_bytes(u8* dest, size_t len);
static void bytes_to_block(aes_block_t* state, const u8* bytes);

#ifndef NDEBUG
static void print_state(const aes_block_t* state);
static void print_bytes(const u8* bytes, const size_t len);
static void print_words(const u32* words, const size_t len);
#endif

// Function bodies
void aes_128_gen_key(u8* k) {
#ifndef NDEBUG
  memcpy(k, test_k, AES_128_KEY_LEN);
#else
  gen_rand_bytes(k, AES_128_KEY_LEN);
#endif
}

aes_ctx_t* aes_128_ctx_init(aes_key_t key) {
  aes_ctx_t* context = (aes_ctx_t*) malloc(sizeof(aes_ctx_t));

  if (context == NULL) {
    fprintf(stderr, "ERROR: couldn't allocate memory for AES context\n");
    return NULL;
  }

  key_expansion(key, context->expanded_key, AES_128_N_RNDS);
  
#ifndef NDEBUG
  memcpy(&(context->nonce), nonce, sizeof(nonce));
  memcpy(&(context->iv), iv, sizeof(iv));
#else
  // Initialize "random" nonce and initialization vector and save it in the context for later decryption
  gen_rand_bytes((u8*) &(context->nonce), sizeof(context->nonce));
  gen_rand_bytes((u8*) &(context->iv), sizeof(context->iv));
#endif
  context->out_len = 0;
  context->output = NULL;
  
#ifndef NDEBUG
  printf("Nonce: ");
  print_bytes((u8*) &(context->nonce), sizeof(context->nonce));
  printf("\n");
  printf("IV: ");
  print_bytes((u8*) &(context->iv), sizeof(context->iv));
  printf("\n");
#endif 

  return context;
}

void aes_128_ctx_free(aes_ctx_t* context) {
  if (context != NULL) {
    if (context->output != NULL) {
      free(context->output);
    }
    free(context);
  }
}

void aes_128_encrypt(aes_ctx_t* context, const u8* input, size_t len) {
#ifndef NDEBUG
  printf("Input: ");
  print_bytes(input, len);
  printf("\n");
#endif

  // Initialize counter block using nonce, initialization vector and counter
  aes_block_t ctr_block;
  init_counter_block(&ctr_block, context);

  // Compute number of blocks to be ciphered
  u32 last_block_len = (len % sizeof(aes_block_t) > 0);
  size_t n_blocks = len/sizeof(aes_block_t); // Insert truncaded number of blocks
  n_blocks += (last_block_len > 0);          // If m does not fit perfectly in the blocks
                                             // add another block with padding

  // Copy input into output to facilitate XOR operations with the cipher result
  if (context->output == NULL) {
    context->output = calloc(n_blocks * sizeof(aes_block_t), sizeof(u8));
  }

  if (context->output == NULL) {
    fprintf(stderr, "ERROR: couldn't allocate memory for output stream\n");
    return;
  }
  memcpy(context->output, input, len);
  context->out_len = len;
  
  // Operate over every block except the last, because it may need to be truncated
  aes_block_t res; 
  size_t block_idx = 0;
  for (size_t i = 0; i < n_blocks; i++) {
    res = ctr_block;
    cipher(&res, AES_128_N_RNDS, context->expanded_key);
    xor_block_into_bytes(&(context->output[block_idx]), &res);
    increment_counter(&ctr_block);
    block_idx += sizeof(aes_block_t);
#ifndef NDEBUG
    printf("Counter block (%ld):\n", i+1);
    print_state(&ctr_block);
    printf("\n");
    printf("Key Stream (%ld):\n", i+1);
    print_state(&res);
    printf("\n");
#endif
  }
  
#ifndef NDEBUG
  printf("Output: ");
  print_bytes(context->output, len);
  printf("\n");
#endif
}

void aes_128_decrypt(aes_ctx_t* context, const u8* input, size_t len) {
  // Since we are using CTR-mode, decryption trivial
  aes_128_encrypt(context, input, len);
}

// Private function bodies

static void init_counter_block(aes_block_t* counter_block, aes_ctx_t* context) {
  /* Inserts bytes into the block according to the following diagram, where nonce and counter
   * are a 32 bit value and the initialization vector is a 64 bit value:
   * 
   * 0                   1                   2                   3
   * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   * +---------------------------------------------------------------+
   * |                            Nonce                              |
   * +---------------------------------------------------------------+
   * |                  Initialization Vector (IV)                   |
   * |                                                               |
   * +---------------------------------------------------------------+
   * |                         Block Counter                         |
   * +---------------------------------------------------------------+ 
   *  
   * Please note that the representation presented in the RFC (Section 4) used as reference
   * uses a big-endian 32 bit integer value, meaning that our counter should start MSB first,
   * but our target architecture (x86 LSB-first) encodes memory in little-endian. This means 
   * that we need to initialize and operate on our counter MSB-first to comply with the RFC
   * used as reference. */
  u32 counter_block_words[sizeof(aes_block_t) / sizeof(u32)];
  counter_block_words[0] = context->nonce;
  counter_block_words[1] = context->iv & 0xFFFFFFFF;
  counter_block_words[2] = context->iv >> 32;
  counter_block_words[3] = 0x01000000; // Initialize counter as ONE LSB-first
  bytes_to_block(counter_block, (u8*) counter_block_words);
}

static void cipher(aes_block_t* state, const int n_rnds, u32* expanded_key) {
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
}

static void add_round_key(aes_block_t* state, const u32* round_key) {
  const u8* round_key_bytes = (u8*) round_key;
  xor_bytes_into_block(state, round_key_bytes);
}

static void sub_bytes(aes_block_t* state) {
  for (size_t i = 0; i < 4; i++) {
    state->words[i] = sub_word(state->words[i]);
  }
}

static void shift_rows(aes_block_t* state) {
  for (size_t i = 1; i < 4; i++) {
    state->words[i] = rot_word(state->words[i], i);
  }
}

static void inv_shift_rows(aes_block_t* state) {
  for (size_t i = 1; i < 4; i++) {
    state->words[i] = rot_word(state->words[i], i);
  }
}

static void mix_columns(aes_block_t* state) {
  u8 column[4];
  // Copy original state because it will be modified
  aes_block_t original_state;
  memcpy(&original_state, state, sizeof(aes_block_t));

  for (size_t j = 0; j < 4; j++) {
    for (size_t i = 0; i < 4; i++) {
      column[i] = original_state.bytes[i][j];
    }
    state->bytes[0][j] = gmul(0x02, column[0]) ^ gmul(0x03, column[1]) ^ column[2] ^ column[3];
    state->bytes[1][j] = column[0] ^ gmul(0x02, column[1]) ^ gmul(0x03, column[2]) ^ column[3];
    state->bytes[2][j] = column[0] ^ column[1] ^ gmul(0x02, column[2]) ^ gmul(0x03, column[3]);
    state->bytes[3][j] = gmul(0x03, column[0]) ^ column[1] ^ column[2] ^ gmul(0x02, column[3]);
  }
}

static void increment_counter(aes_block_t* counter_block) {
  /* The last column of the block represets our counter:
   *
   * +----+----+----+======+
   * | NO | IV | IV | C[3] | <- MSB
   * +----+----+----+======+
   * | NO | IV | IV | C[2] |
   * +----+----+----+======+
   * | NO | IV | IV | C[1] |
   * +----+----+----+======+
   * | NO | IV | IV | C[9] |
   * +----+----+----+======+ */
  u32 new_counter = (counter_block->bytes[0][3] << 24 |
                     counter_block->bytes[1][3] << 18 |
                     counter_block->bytes[2][3] << 8  |
                     counter_block->bytes[3][3]) + 1;
  counter_block->bytes[3][3] = new_counter & 0xFF;
  counter_block->bytes[2][3] = (new_counter >> 8) & 0xFF;
  counter_block->bytes[1][3] = (new_counter >> 16) & 0xFF;
  counter_block->bytes[0][3] = (new_counter >> 24) & 0xFF;
}

static u32 rot_word(u32 word, const int times) {
  u32 temp;

  for (size_t i = 0; i < times; i++) {
      temp = word;
      word = word >> BYTE_LEN;
      word = word | (temp & 0xFF) << (3*BYTE_LEN);
  }
  return word;
}

static u32 inv_rot_word(u32 word, const int times) {
  u32 temp;

  for (size_t i = 0; i < times; i++) {
      temp = word;
      word = word << BYTE_LEN;
      word = word | (temp & 0xFF) >> (3*BYTE_LEN);
  }
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

static void xor_block_into_bytes(u8* bytes, const aes_block_t* state) {
  size_t bcounter = 0;
  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < 4; j++) {
      bytes[bcounter++] ^= state->bytes[j][i];
    }
  }
}

static void xor_bytes_into_block(aes_block_t* state, const u8* bytes) {
  size_t bcounter = 0;
  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < 4; j++) {
      state->bytes[j][i] ^= bytes[bcounter++];
    }
  }
}

static void gen_rand_bytes(u8* dest, size_t len) {
  for (size_t i = 0; i < len; i++) {
    dest[i] = rand() % 0x100;
  }
}

static void bytes_to_block(aes_block_t* state, const u8* bytes) {
  size_t bcounter = 0;
  for (size_t i = 0; i < 4; i++) {
    for (size_t j = 0; j < 4; j++) {
      state->bytes[j][i] = bytes[bcounter++];
    }
  }
}

#ifndef NDEBUG
static void print_state(const aes_block_t* state) {
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
