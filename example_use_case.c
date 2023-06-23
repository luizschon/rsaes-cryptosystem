#include "aes.h"

int main(int argc, char** argv) {
  uint8_t aes_key[AES_128_KEY_LEN];
  aes_128_gen_key(aes_key);
  aes_128_encrypt((uint8_t*) "", (uint8_t*) "", aes_key);

  return 0;
}
