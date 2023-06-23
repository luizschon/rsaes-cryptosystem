#ifndef __AES_H
#define __AES_H

#include <stddef.h> // For size_t
#include <stdint.h>

#define AES_128_KEY_LEN 16

void aes_128_gen_key(uint8_t*);
void aes_128_encrypt(const uint8_t*, uint8_t*, const size_t, const uint8_t*);
void aes_128_decrypt(const uint8_t*, uint8_t*, const uint8_t*);

#endif // __AES_H
