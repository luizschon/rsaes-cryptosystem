#include "common.h"
#include "aes.h"
#include "rsa.h"

#define SIZE AES_128_KEY_LEN

int main(int argc, char** argv) {
  u8 aes_key[AES_128_KEY_LEN];
  aes_128_gen_key(aes_key);

  u8 message[SIZE] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

  u8 cryptogram[SIZE];
  aes_128_encrypt(message, cryptogram, SIZE, aes_key);
  //rsa_gen_pq();
  //rsa_sign();
  //rsa_verify();
  //aes_128_decrypt(cryptogram, message, aes_key);
  // da uma olhada depois

  return 0;
}
