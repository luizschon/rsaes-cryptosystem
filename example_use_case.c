#include "common.h"
#include "aes.h"
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

#define SIZE AES_128_KEY_LEN

int main(int argc, char** argv) {
  u8 aes_key[AES_128_KEY_LEN];
  aes_128_gen_key(aes_key);

  u8 message[0x24];
  for (size_t i = 0; i < sizeof(message); i++) {
    message[i] = i;
  }

  aes_ctx_t* aes_context = aes_128_ctx_init(aes_key);
  aes_128_encrypt(aes_context, message, 0x24);
  aes_128_decrypt(aes_context, aes_context->output, aes_context->out_len);
  aes_128_ctx_free(aes_context);

  rsa_ctx_t* rsa_context = rsa_ctx_init();
  rsa_oaep_sha256_encrypt(rsa_context, message, 0x24);
  rsa_ctx_free(rsa_context);

  return 0;
}
