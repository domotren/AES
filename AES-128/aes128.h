#ifndef _AES_128_H_
#define _AES_128_H_

#include "../aes.h"

extern uint8_t aes_key[N_AES_KEY_SIZE];

void aes_key_init(uint8_t *key);
uint8_t *aes_encryption(uint8_t *plain, uint32_t plain_size,
                        uint32_t *cipher_size);
uint8_t *aes_decryption(uint8_t *cipher, uint32_t cipher_size,
                        uint32_t *plain_size);

#endif // _AES_128_H_
