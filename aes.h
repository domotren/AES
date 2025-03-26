#ifndef _AES_H_
#define _AES_H_

#include "Format/format.h"
#include "Padding/padding.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ALGO_AES_128
// #define ALGO_AES_192
// #define ALGO_AES_256

#define TYPE_AES_ECB
// #define TYPE_AES_CBC
// #define TYPE_AES_GCM

#define N_AES_STATE_SIZE 16

#if defined(ALGO_AES_128)
#define N_AES_KEY_SIZE 16
#define N_AES_ROUND 10
#define N_AES_KEY_EXPAND_SIZE 176
#elif defined(ALGO_AES_192)
#define N_AES_KEY_SIZE 24
#define N_AES_ROUND 12
#define N_AES_KEY_EXPAND_SIZE 208
#elif defined(ALGO_AES_256)
#define N_AES_KEY_SIZE 32
#define N_AES_ROUND 14
#define N_AES_KEY_EXPAND_SIZE 240
#endif

extern const uint8_t rijndael_s_box[256];
extern const uint8_t rijndael_inverse_s_box[256];
extern const uint8_t rijndael_r_con[];

#endif // _AES_H_