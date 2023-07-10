#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cryptosystem.h"
#include "common.h"

void cs_result_free(cs_result_t* result) {
  if (result != NULL) {
    if (result->output != NULL) {
      free(result->output);
    }
    free(result);
  }
}

cs_result_t* cs_hybrid_encrypt(aes_ctx_t* aes_ctx, mpz_t rsa_mod, mpz_t rsa_exp, const u8* msg, size_t len) {
  cs_result_t* res = (cs_result_t*) malloc_or_panic(sizeof(cs_result_t));

  // Cipher message with AES
  aes_result_t* aes_result = aes_128_encrypt(aes_ctx, msg, len);

  // Saves AES params into its own struct to facilitate usage
  aes_params_t aes_params = { .iv = aes_ctx->iv, .nonce = aes_ctx->nonce };
  memcpy(&(aes_params.key), aes_ctx->key, sizeof(aes_key_t));

  // Cipher aes params using RSA public key
  rsa_result_t* rsa_result = rsa_encrypt(rsa_mod, rsa_exp, (u8*) &aes_params, sizeof(aes_params));

  // We will add the encrypted AES message and the RSA encrypted AES params into the resulting cryptogram
  res->len = aes_result->len + rsa_result->len;
  res->output = (u8*) malloc_or_panic(res->len);
  memcpy(res->output, aes_result->output, aes_result->len);
  memcpy(res->output + aes_result->len, rsa_result->output, rsa_result->len);

  aes_res_free(aes_result);
  rsa_result_free(rsa_result);

  return res;
}
cs_result_t* cs_hybrid_decrypt(mpz_t mod, mpz_t exp, const u8* crypt, size_t len) {
  cs_result_t* res = (cs_result_t*) malloc_or_panic(sizeof(cs_result_t));
  size_t n_len = sizeof_mpz(mod);

  // Since the aes params in the end of the cryptogram amount to only 28 bytes, we can be sure
  // that the last n_len bytes are the RSA encrypted AES params
  size_t rsa_dec_offset = len - n_len;
  rsa_result_t* rsa_result = rsa_decrypt(mod, exp, crypt + rsa_dec_offset, n_len);

  // Extracts aes_params from decrypted RSA message
  aes_params_t aes_params;
  memcpy(&aes_params, rsa_result->output, sizeof(aes_params));

  // Decrypt AES message in the beginning of the cryptogram using the params provided
  aes_ctx_t* aes_ctx = aes_128_ctx_init((aes_key_t*) aes_params.key, &(aes_params.iv), &(aes_params.nonce));
  aes_result_t* aes_result = aes_128_decrypt(aes_ctx, crypt, len - n_len);

  // Allocates memory to store the result of the whole decipher process
  res->len = aes_result->len;
  res->output = (u8*) malloc_or_panic(res->len);
  memcpy(res->output, aes_result->output, res->len);

  rsa_result_free(rsa_result);
  aes_res_free(aes_result);
  aes_128_ctx_free(aes_ctx);

  return res;
}

cs_result_t* cs_auth_hybrid_encrypt(aes_ctx_t* aes_ctx, rsa_key_t sender_pub, rsa_key_t sender_sec, rsa_key_t rec_pub, const u8* msg, size_t len) {
  cs_result_t* res = (cs_result_t*) malloc_or_panic(sizeof(cs_result_t));

  // Cipher message with AES
  aes_result_t* aes_result = aes_128_encrypt(aes_ctx, msg, len);

  // Saves AES params into its own struct to facilitate usage
  aes_params_t aes_params = { .iv = aes_ctx->iv, .nonce = aes_ctx->nonce };
  memcpy(&(aes_params.key), aes_ctx->key, sizeof(aes_key_t));

  // Cipher AES params using reciever public key
  rsa_result_t* rsa_result = rsa_encrypt(*(rec_pub.mod), *(rec_pub.exp), (u8*) &aes_params, sizeof(aes_params));

  // Cipher AGAIN using the sender private key
  rsa_result_t* rsa_result2 = rsa_encrypt(*(sender_sec.mod), *(sender_sec.exp), rsa_result->output, rsa_result->len);

  // We will add the encrypted AES message, the RSA multually authenticated encrypted AES params
  // and the sender RSA public key to the cryptogram  
  res->len = aes_result->len + rsa_result2->len + (RSA_MOD_LEN + RSA_PUB_LEN);
  res->output = (u8*) malloc_or_panic(res->len);
  memcpy(res->output, aes_result->output, aes_result->len);
  memcpy(res->output + aes_result->len, rsa_result2->output, rsa_result2->len);
  u8 key_bytes[RSA_MOD_LEN + RSA_PUB_LEN];
  rsa_export_key(key_bytes, sender_pub);
  memcpy(res->output + aes_result->len + rsa_result2->len, key_bytes, sizeof(key_bytes));

  aes_res_free(aes_result);
  rsa_result_free(rsa_result);
  rsa_result_free(rsa_result2);
  
  return res;
}

cs_result_t* cs_auth_hybrid_decrypt(rsa_key_t rec_sec, const u8* crypt, size_t len) {
  cs_result_t* res = (cs_result_t*) malloc_or_panic(sizeof(cs_result_t));

  // Grab the last bytes corresponding to the RSA public key of the sender and import then 
  // into the representative format
  size_t key_offset = len - (RSA_MOD_LEN + RSA_PUB_LEN);
  mpz_t sender_mod, sender_exp;
  mpz_inits(sender_mod, sender_exp, NULL);
  rsa_import_key(sender_mod, sender_exp, crypt + key_offset);

  size_t n_len = RSA_MOD_LEN;
  size_t h_len = SHA256_DIGEST_LEN;

  // Calculates number of blocks that corresponds to the encryption with mutual authentication
  // of the AES params. Since AES params fills 28 bytes, the resulting cipher is n_len 
  // long. This is again ciphered using the sender secret key, totaling 2*n_len
  size_t max_crypt_len = n_len - 2*h_len - 2;

  size_t n_blocks = n_len / max_crypt_len;
  bool should_add_partial_block = (n_len % max_crypt_len > 0);
    n_blocks += should_add_partial_block;
  
  size_t rsa_block_offset = len - (RSA_MOD_LEN + RSA_PUB_LEN) - (n_blocks * n_len);
  rsa_result_t* rsa_result = rsa_decrypt(sender_mod, sender_exp, crypt + rsa_block_offset, n_blocks * n_len);
  rsa_result_t* rsa_result2 = rsa_decrypt(*(rec_sec.mod), *(rec_sec.exp), rsa_result->output, rsa_result->len);

  // Extracts aes_params from decrypted RSA message
  aes_params_t aes_params;
  memcpy(&aes_params, rsa_result2->output, sizeof(aes_params));

  // Decrypt AES message in the beginning of the cryptogram using the params provided
  size_t crypt_size = len - (RSA_MOD_LEN + RSA_PUB_LEN) - (n_blocks * n_len);
  aes_ctx_t* aes_ctx = aes_128_ctx_init((aes_key_t*) aes_params.key, &(aes_params.iv), &(aes_params.nonce));
  aes_result_t* aes_result = aes_128_decrypt(aes_ctx, crypt, crypt_size);

  // Allocates memory to store the result of the whole decipher process
  res->len = aes_result->len;
  res->output = (u8*) malloc_or_panic(res->len);
  memcpy(res->output, aes_result->output, res->len);

  mpz_clears(sender_exp, sender_mod, NULL);
  rsa_result_free(rsa_result);
  rsa_result_free(rsa_result2);
  aes_128_ctx_free(aes_ctx);
  aes_res_free(aes_result);

  return res; 
}

cs_result_t* cs_sign(aes_ctx_t* aes_ctx, rsa_key_t signer_pub, rsa_key_t signer_sec, const u8* msg, size_t len) {
  cs_result_t* res = (cs_result_t*) malloc_or_panic(sizeof(cs_result_t));

  // Cipher message with AES
  aes_result_t* aes_result = aes_128_encrypt(aes_ctx, msg, len);

  // Cipher HASH of the AES cipher result
  u8* cipher_hash;
  sha3_256_wrapper(aes_result->output, aes_result->len, &cipher_hash);
  rsa_result_t* rsa_result = rsa_encrypt(*(signer_sec.mod), *(signer_sec.exp), cipher_hash, SHA256_DIGEST_LEN);

  printf("HASH(AES_k(M)):\n");
  print_bytes(cipher_hash, SHA256_DIGEST_LEN);
  printf("\n");

  // We will add the encrypted AES message, the RSA encrypted AES cipher hash and signer public
  // key into the resulting cryptogram
  res->len = aes_result->len + rsa_result->len + (RSA_MOD_LEN + RSA_PUB_LEN);
  res->output = (u8*) malloc_or_panic(res->len);
  memcpy(res->output, aes_result->output, aes_result->len);
  memcpy(res->output + aes_result->len, rsa_result->output, rsa_result->len);
  memcpy(res->output + aes_result->len, rsa_result->output, rsa_result->len);

  memcpy(res->output, aes_result->output, aes_result->len);
  memcpy(res->output + aes_result->len, rsa_result->output, rsa_result->len);
  u8 key_bytes[RSA_MOD_LEN + RSA_PUB_LEN];
  rsa_export_key(key_bytes, signer_pub);
  memcpy(res->output + aes_result->len + rsa_result->len, key_bytes, sizeof(key_bytes));

  sha3_256_free(cipher_hash);
  aes_res_free(aes_result);
  rsa_result_free(rsa_result);

  return res;
}

bool cs_vrfy(const u8* expected_hash, const u8* crypt, size_t len) {
  // Grab the last bytes corresponding to the RSA public key of the sender and import then 
  // into the representative format
  size_t key_offset = len - (RSA_MOD_LEN + RSA_PUB_LEN);
  mpz_t signer_mod, signer_exp;
  mpz_inits(signer_mod, signer_exp, NULL);
  rsa_import_key(signer_mod, signer_exp, crypt + key_offset);

  // Since the digest of the hashing function used in the signature generation (SHA256) is only
  // 32 bytes long, the resulted ciphered RSA block must be RSA_MOD_LEN long
  size_t rsa_block_offset = len - (RSA_MOD_LEN + RSA_PUB_LEN) - RSA_MOD_LEN;
  rsa_result_t* rsa_result = rsa_decrypt(signer_mod, signer_exp, crypt + rsa_block_offset, RSA_MOD_LEN);

  printf("Expected hash:\n");
  print_bytes(expected_hash, SHA256_DIGEST_LEN);
  printf("\n");
  printf("Deciphered hash:\n");
  print_bytes(rsa_result->output, SHA256_DIGEST_LEN);
  printf("\n");

  bool res = true;

  // Compares the result of the decryption with the expected hash
  for (size_t i = 0; i < SHA256_DIGEST_LEN; i++) {
    if (expected_hash[i] != rsa_result->output[i]) {
      res = false;
      break;
    }
  }

  mpz_clears(signer_exp, signer_mod, NULL);
  rsa_result_free(rsa_result);
  return res;
}