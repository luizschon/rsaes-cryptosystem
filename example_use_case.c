#include "common.h"
#include "aes.h"
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>

#define SIZE AES_128_KEY_LEN

int main(int argc, char** argv) {
  u8 aes_key[AES_128_KEY_LEN];
  aes_128_gen_key(aes_key);

  u8 message[SIZE] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

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
  

  aes_ctx_t* context = aes_128_ctx_init(aes_key, message, SIZE);
  aes_128_encrypt(context);
  // Nao parece viavel, se nao o usuario teria saber previamente o tamanho do plaintext
  // e alem disso teria limpar a memoria
  // aes_128_decrypt(context);
  aes_128_ctx_free(context);

  return 0;
}
