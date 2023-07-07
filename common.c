#include <stdio.h>
#include <openssl/evp.h>
#include "common.h"

void gen_rand_bytes(u8* dest, size_t len) {
  for (size_t i = 0; i < len; i++) {
    dest[i] = rand() % 0x100;
  }
}

void xor_bytes(u8* dest, const u8* src1, const u8* src2, size_t len) {
  for (size_t i = 0; i < len; i++) {
    dest[i] = src1[i] ^ src2[i];
  }
}

void print_bytes(const u8* bytes, const size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x ", bytes[i]);
  }
  printf("\n");
}
 
void print_words(const u32* words, const size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%08x ", words[i]);
  }
  printf("\n");
}

int sizeof_mpz(mpz_t big_int) {
  int n_bits = mpz_sizeinbase(big_int, 2);
  return (n_bits/8 + (n_bits % 8 > 0));
} 

void sha3_256_wrapper(const u8* message, size_t message_len, u8** digest) {
  EVP_MD_CTX* md_ctx;
  
  if((md_ctx = EVP_MD_CTX_new()) == NULL) {
    fprintf(stderr, "ERROR: couldn't allocate memory for EVP_MD context\n");
    exit(1);
  }

  EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(md_ctx, message, message_len);
  *digest = (u8*) OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
  
  if(*digest == NULL) {
    fprintf(stderr, "ERROR: couldn't allocate memory for SHA-3-256 digest\n");
    exit(1);
  }

  unsigned int digest_len;
  EVP_DigestFinal_ex(md_ctx, *digest, &digest_len);
  EVP_MD_CTX_free(md_ctx);

#ifndef NDEBUG
  printf("SHA digest: ");
  print_bytes(*digest, digest_len);
  printf("\n");
#endif
}

void sha3_256_free(u8* digest) {
  if (digest != NULL) {
    OPENSSL_free(digest);
  }
}
