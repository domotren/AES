#ifndef _AES_H_
#define _AES_H_

#include "aes_config.h"

#if defined(TYPE_AES_CTR)
#define N_AES_NONCE_SIZE N_AES_NONCE_SIM
#endif

extern uint8_t aes_key[N_AES_KEY_SIZE];

void aes_key_init(uint8_t *key);
#if defined(TYPE_AES_CBC)
void aes_iv_init(uint8_t *init_vector);
#endif
#if defined(TYPE_AES_CTR)
void aes_nonce_init(uint8_t *nonce);
#endif
uint8_t *aes_encryption(uint8_t *plain, uint32_t plain_size,
                        uint32_t *cipher_size);
uint8_t *aes_decryption(uint8_t *cipher, uint32_t cipher_size,
                        uint32_t *plain_size);

#endif // _AES_H_
