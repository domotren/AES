#ifndef _AES_128_H_
#define _AES_128_H_

#include "../aes.h"

extern uint8_t aes_round_key[N_AES_KEY_EXPAND_SIZE];
extern uint8_t aes_key[N_AES_KEY_SIZE];

void aes_init(uint8_t *round_key, uint8_t *key);
void aes_encryption(uint8_t *plain_text, uint8_t *round_key, uint8_t *output);
void aes_decryption(uint8_t *cipher_text, uint8_t *round_key, uint8_t *output);

#endif // _AES_128_H_
