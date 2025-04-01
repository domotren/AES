#ifndef _AES_H_
#define _AES_H_

#include "aes_config.h"

#if defined(TYPE_AES_CTR)
#define N_AES_NONCE_SIZE N_AES_NONCE_SIM
#endif

#if defined(TYPE_AES_GCM)
#define N_AES_IV_SIZE 12
#endif

enum aes_error {
        AES_SUCCESS,
        AES_INVALID_CONTEXT,
        AES_INVALID_INPUT,
        AES_MALLOC_FAIL,
};

struct aes_ctx {
        uint32_t input_len;
        uint32_t output_len;
        uint8_t *input;
        uint8_t *output;
        uint8_t aes_key[N_AES_KEY_SIZE];
#if defined(TYPE_AES_CBC)
        uint8_t aes_init_vector[N_AES_STATE_SIZE];
#endif
#if defined(TYPE_AES_CTR)
        uint8_t aes_nonce[N_AES_NONCE_SIZE];
#endif
        uint8_t aes_round_key[N_AES_KEY_EXPAND_SIZE];
};

void aes_key_init(struct aes_ctx *ctx, uint8_t *key);
enum aes_error aes_context_release(struct aes_ctx *ctx);
#if defined(TYPE_AES_CBC)
void aes_iv_init(struct aes_ctx *ctx, uint8_t *iv);
#endif
#if defined(TYPE_AES_CTR)
void aes_nonce_init(struct aes_ctx *ctx, uint8_t *nonce);
#endif
#if defined(TYPE_AES_GCM)
void aes_ghash_h_init(void);
void aes_j0_init(uint8_t *iv, uint32_t iv_size);
#endif

#if defined(TYPE_AES_ECB) || defined(TYPE_AES_GCM)
enum aes_error aes_ecb_encryption(struct aes_ctx *ctx);
#endif
#if defined(TYPE_AES_ECB)
enum aes_error aes_ecb_decryption(struct aes_ctx *ctx);
#endif
#if defined(TYPE_AES_CBC)
enum aes_error aes_cbc_encryption(struct aes_ctx *ctx);
enum aes_error aes_cbc_decryption(struct aes_ctx *ctx);
#endif
#if defined(TYPE_AES_CTR)
enum aes_error aes_ctr_encryption(struct aes_ctx *ctx);
#endif
#if defined(TYPE_AES_GCM)
uint8_t *aes_gcm_encryption(uint8_t *aad, uint32_t aad_len, uint8_t *plain,
                            uint32_t plain_len, uint32_t *cipher_len);
// uint8_t *aes_gcm_decryption(uint8_t *cipher, uint32_t cipher_size,
                            // uint32_t *plain_size);
#endif
#endif // _AES_H_
