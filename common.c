#include <stdio.h>
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