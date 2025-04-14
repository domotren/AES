#ifndef AES_CONFIG_H_INCLUDED
#define AES_CONFIG_H_INCLUDED

#include "format.h"
#include "padding.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define N_AES_STATE_SIZE 16

#define N_AES_NONCE_NIST 12
#define N_AES_NONCE_SIM 16

#if defined(TYPE_AES_128)
#define N_AES_KEY_SIZE 16
#define N_AES_ROUND 10
#define N_AES_KEY_EXPAND_SIZE 176
#elif defined(TYPE_AES_192)
#define N_AES_KEY_SIZE 24
#define N_AES_ROUND 12
#define N_AES_KEY_EXPAND_SIZE 208
#elif defined(TYPE_AES_256)
#define N_AES_KEY_SIZE 32
#define N_AES_ROUND 14
#define N_AES_KEY_EXPAND_SIZE 240
#endif

extern const uint8_t rijndael_s_box[256];
extern const uint8_t rijndael_inverse_s_box[256];
extern const uint8_t rijndael_r_con[];

#endif // AES_CONFIG_H_INCLUDED