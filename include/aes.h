#ifndef __AES_H
#define __AES_H

#include <stddef.h> // For size_t
#include "common.h"

#define AES_128_KEY_LEN 16

void aes_128_gen_key(u8*);
void aes_128_encrypt(const u8*, u8*, const size_t, const u8*);
void aes_128_decrypt(const u8*, u8*, const u8*);

#endif // __AES_H
