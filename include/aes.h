#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include "aes_config.h"

#if defined(TYPE_AES_CTR)
#define N_AES_NONCE_SIZE N_AES_NONCE_SIM
#endif

#if defined(TYPE_AES_GCM)
#define N_AES_IV_SIZE 12
#define N_AES_TAG_SIZE 16
#endif

enum aes_error {
        AES_SUCCESS,
        AES_INVALID_CONTEXT,
        AES_INVALID_INPUT,
        AES_INVALID_TAG_INPUT,
        AES_MALLOC_FAIL,
        AES_UNCLEARED_OUTPUT,
        AES_ILLEGAL_LEN,
        AES_ILLEGAL_TAG
};

struct aes_ctx {
        uint8_t *input;
        uint8_t *output;
#if defined(TYPE_AES_GCM)
        uint8_t *aad;
        uint64_t aad_len;
#endif
        uint64_t input_len;
        uint64_t output_len;
        uint8_t key[N_AES_KEY_SIZE];
#if defined(TYPE_AES_CBC)
        uint8_t init_vector[N_AES_STATE_SIZE];
#endif
#if defined(TYPE_AES_CTR)
        uint8_t nonce[N_AES_NONCE_SIZE];
#endif
#if defined(TYPE_AES_GCM)
        uint8_t j0[N_AES_STATE_SIZE];
        uint8_t ghash_h[N_AES_STATE_SIZE];
        uint8_t tag[N_AES_TAG_SIZE];
#endif
        uint8_t round_key[N_AES_KEY_EXPAND_SIZE];
#if defined(TYPE_AES_GCM)
        uint8_t tag_len;
#endif
};

void aes_init_key(struct aes_ctx *ctx, uint8_t *key);
enum aes_error aes_context_release(struct aes_ctx *ctx);
#if defined(TYPE_AES_CBC)
void aes_init_iv(struct aes_ctx *ctx, uint8_t *iv);
#endif
#if defined(TYPE_AES_CTR)
void aes_init_nonce(struct aes_ctx *ctx, uint8_t *nonce);
#endif
#if defined(TYPE_AES_GCM)
enum aes_error aes_init_aad(struct aes_ctx *ctx, uint8_t *aad,
                            uint64_t aad_len);
enum aes_error aes_init_ghash_h(struct aes_ctx *ctx);
enum aes_error aes_init_j0(struct aes_ctx *ctx, uint8_t *iv, uint64_t iv_len);
enum aes_error aes_init_tag(struct aes_ctx *ctx, uint8_t *tag, uint8_t tag_len);
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
enum aes_error aes_gcm_encryption(struct aes_ctx *ctx);
enum aes_error aes_gcm_decryption(struct aes_ctx *ctx);
#endif
#endif // AES_H_INCLUDED
