#include "common.h"
#include "aes.h"
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE AES_128_KEY_LEN

int main(int argc, char** argv) {
  u8 aes_key[AES_128_KEY_LEN];
  aes_128_gen_key(aes_key);

  u8 message[0x24];
  for (size_t i = 0; i < sizeof(message); i++) {
    message[i] = i;
  }

  // u8* cryptogram = aes_128_encrypt(message, SIZE, aes_key);
  // for (size_t i = 0; i < SIZE; i++) {
  //   printf("%02x ", cryptogram[i]);
  // }
  // printf("\n");
  // free(cryptogram);
  //rsa_gen_pq();
  //rsa_sign();
  //rsa_verify();
  //aes_128_decrypt(cryptogram, message, aes_key);
  // da uma olhada depois
  

  aes_ctx_t* context = aes_128_ctx_init(aes_key);
  aes_128_encrypt(context, message, 0x24);
  aes_128_decrypt(context, context->output, context->out_len);
  aes_128_ctx_free(context);

  return 0;
}
