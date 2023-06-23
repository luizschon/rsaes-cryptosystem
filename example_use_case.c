#include "aes.h"

#define SIZE 54

int main(int argc, char** argv) {
  uint8_t aes_key[AES_128_KEY_LEN];
  aes_128_gen_key(aes_key);

  uint8_t message[SIZE];
  for (size_t i = 0; i < SIZE; i++) {
    message[i] = i+1;
  }
  
  aes_128_encrypt(message, (uint8_t*) "", SIZE, aes_key);

  return 0;
}
