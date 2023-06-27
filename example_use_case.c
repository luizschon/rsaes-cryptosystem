#include "aes.h"
#include "rsa.h"

#define SIZE 54

int main(int argc, char** argv) {
  uint8_t aes_key[AES_128_KEY_LEN];
  aes_128_gen_key(aes_key);

  uint8_t message[SIZE];
  for (size_t i = 0; i < SIZE; i++) {
    message[i] = i+1;
  }

  uint8_t cryptogram[SIZE];
  aes_128_encrypt(message, cryptogram, SIZE, aes_key);
  //rsa_gen_pq();
  //rsa_sign();
  //rsa_verify();
  //aes_128_decrypt(cryptogram, message, aes_key);
  // da uma olhada depois

  return 0;
}
