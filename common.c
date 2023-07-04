#include <stdio.h>
#include <openssl/evp.h>
#include "common.h"

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

void sha3_256_wrapper(const u8* message, size_t message_len, u8** digest, size_t* digest_len) {
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

  EVP_DigestFinal_ex(md_ctx, *digest, (unsigned int*) digest_len);

	EVP_MD_CTX_free(md_ctx);
}

void sha3_256_free(u8* digest) {
  if (digest != NULL) {
    OPENSSL_free(digest);
  }
}