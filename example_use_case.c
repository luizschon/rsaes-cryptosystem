#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/crypto.h>
#include "cryptosystem.h"
#include "common.h"

#define MAX_SIZE 1024

int main(int argc, char** argv) {
  char message[MAX_SIZE];
  printf("Enter plaintext: ");
  if (fgets(message, sizeof(message), stdin) == NULL) {
    exit(1);
  }

  // Adds null-byte to the end of the string
  size_t message_len = strlen(message) + 1;

  /*
   * 1) AES cipher message: C = AES_k(M)
   */
  printf("--- USE CASE 1 --------------------------------\n\n");
  printf("AES 128 ecryption and decryption:\n\n");
  printf("    C = AES_k(M)\n\n");

  aes_ctx_t* aes_context = aes_128_ctx_init(NULL, NULL, NULL);
  aes_result_t* aes_encrypt = aes_128_encrypt(aes_context, message, message_len);
  aes_result_t* aes_decrypt = aes_128_decrypt(aes_context, aes_encrypt->output, aes_encrypt->len);
  printf("AES 128 cipher result:\n");
  print_bytes(aes_encrypt->output, aes_encrypt->len);
  printf("\n");
  printf("AES 128 decipher result:\n");
  print_bytes(aes_decrypt->output, aes_decrypt->len);
  printf("As char: %s\n\n", aes_decrypt->output);
  aes_res_free(aes_decrypt);
  aes_res_free(aes_encrypt);
  aes_128_ctx_free(aes_context);

  /*
   * 2) Hybrid cipher using AES and RSA: C = (AES_k(M) , RSA_KA_p(k)) 
   */
  printf("--- USE CASE 2 --------------------------------\n\n");
  printf("Hybrid cipher using AES 128 and RSA:\n\n");
  printf("    C = (AES_k(M), RSA_KA_p(k)\n\n");

  // Initializes RSA context for user A and B (this generates private and public keys for both)
  rsa_ctx_t* user_a = rsa_ctx_init();
  rsa_ctx_t* user_b = rsa_ctx_init();

  // Encrypt message using public key pair of user A
  aes_ctx_t* new_aes_context = aes_128_ctx_init(NULL, NULL, NULL);
  cs_result_t* res2a = cs_hybrid_encrypt(new_aes_context, user_a->n, user_a->e, message, message_len);

  printf("Encrypting message to user A:\n");
  print_bytes(res2a->output, res2a->len);
  printf("\n");

  // Now decrypt message using secret key pair of user A (simulate user A recieving the message)
  cs_result_t* res2b = cs_hybrid_decrypt(user_a->n, user_a->d, res2a->output, res2a->len);
  printf("Decrypted message recieved by user A:\n");
  print_bytes(res2b->output, res2b->len);
  printf("As char: %s\n\n", res2b->output);

  aes_128_ctx_free(new_aes_context);
  cs_result_free(res2a);
  cs_result_free(res2b);

  /*
   * 3) Hybrid encryption with multual authentication: C = (AES_k(M) , RSA_KB_s(RSA_KA_p(k)), KB_p) 
   */
  printf("--- USE CASE 3 --------------------------------\n\n");
  printf("Hybrid cipher with mutual authentication:\n\n");
  printf("    C = (AES_k(M), RSA_KB_s(RSA_KA_p(k)), KB_p)\n\n");

  aes_ctx_t* newer_aes_context = aes_128_ctx_init(NULL, NULL, NULL);
  cs_result_t* res3a = cs_auth_hybrid_encrypt(newer_aes_context, user_b->pub, user_b->sec, user_a->pub, message, message_len);

  printf("Encrypting message to user A:\n");
  print_bytes(res3a->output, res3a->len);
  printf("\n");

  // Now decrypt message using secret key pair of user A (simulate user A recieving the message)
  cs_result_t* res3b = cs_auth_hybrid_decrypt(user_a->sec, res3a->output, res3a->len);
  printf("Decrypted message recieved by user A:\n");
  print_bytes(res3b->output, res3b->len);
  printf("As char: %s\n\n", res3b->output);

  aes_128_ctx_free(newer_aes_context);
  cs_result_free(res3a);
  cs_result_free(res3b);

  /*
   * 4) Signing message: Sign = (AES_k(M), RSA_KA_s(H(AES_k(M))), KA_p) 
   */
  printf("--- USE CASE 4 --------------------------------\n\n");
  printf("Message signing with RSA and AES cipher hashing:\n\n");
  printf("    Sign = (AES_k(M), RSA_KA_s(H(AES_k(M))), KB_p)\n\n");

  aes_ctx_t* final_aes_context = aes_128_ctx_init(NULL, NULL, NULL);
  cs_result_t* res4 = cs_sign(final_aes_context, user_a->pub, user_a->sec, message, message_len);

  printf("Result of signature by user A:\n");
  print_bytes(res4->output, res4->len);
  printf("\n");


  /*
   * 4) Signing message: Sign = (AES_k(M), RSA_KA_s(H(AES_k(M))), KA_p) 
   */
  printf("--- USE CASE 5 --------------------------------\n\n");
  printf("Verify signature:\n\n");
  printf("    RSA_KA_s (RSA_KA_s(H(AES_k(M)))) = H(AES_k(M))\n\n");

  aes_result_t* aes_for_hash = aes_128_encrypt(final_aes_context, message, message_len);
  u8* expected_hash;
  sha3_256_wrapper(aes_for_hash->output, aes_for_hash->len, &expected_hash);
  assert(cs_vrfy(expected_hash, res4->output, res4->len) == true);

  cs_result_free(res4);
  sha3_256_free(expected_hash);
  aes_res_free(aes_for_hash);
  aes_128_ctx_free(final_aes_context);

  rsa_ctx_free(user_a);
  rsa_ctx_free(user_b);

  return 0;
}
