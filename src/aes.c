
#include "aes.h"

static void aes_key_expansion(uint8_t *round_key, const uint8_t *key);
#if defined(TYPE_AES_CBC)
static void aes_step_cbc_pre_block_xor(uint8_t *state, uint8_t *vector);
#endif
#if defined(TYPE_AES_CTR) || defined(TYPE_AES_GCM)
static void aes_step_ctr_key_stream_xor(uint8_t *state, uint8_t *key_stream);
#endif
static void aes_step_sub_bytes(uint8_t *state);
static void aes_step_shift_rows(uint8_t *state);
static void aes_step_mix_columns(uint8_t *state);
static void aes_step_add_round_key(uint8_t *state, uint8_t *round_key);
#if (!defined(TYPE_AES_CTR) && !defined(TYPE_AES_GCM))
static void aes_step_inv_sub_bytes(uint8_t *state);
static void aes_step_inv_shift_rows(uint8_t *state);
static void aes_step_inv_mix_columns(uint8_t *state);
#endif
static uint8_t gf8_multiply(uint8_t a, uint8_t b);
#if defined(TYPE_AES_GCM)
static void be_set_u64(uint8_t *x, uint64_t val);
static void be_set_u32(uint8_t *x, uint32_t val);
static inline uint32_t be_get_u32(const uint8_t *x);
static void gf128_right_shift(uint8_t *v);
static void gf128_multiply(uint8_t *x, uint8_t *y, uint8_t *z);
static void ghash(uint8_t *h, uint8_t *data, size_t data_len, uint8_t *y);
#endif
#if defined(TYPE_AES_GCM) || defined(TYPE_AES_CTR)
static void increment_uint128(uint8_t *bytes);
#endif

/**
 * @brief       clear AES context
 * @param       *ctx: must be a valid object
 * @return      aes_error
 */
enum aes_error aes_context_release(struct aes_ctx *ctx)
{
        if (ctx == NULL) {
                return AES_INVALID_CONTEXT;
        }

        memset(ctx->key, 0x00, N_AES_KEY_SIZE);
        memset(ctx->round_key, 0x00, N_AES_KEY_EXPAND_SIZE);
#if defined(TYPE_AES_CBC)
        memset(ctx->init_vector, 0x00, N_AES_KEY_SIZE);
#endif
#if defined(TYPE_AES_GCM)
        if (ctx->aad_len > 0) {
                free(ctx->aad);
                ctx->aad_len = 0;
        }
#endif
        free(ctx->output);
        ctx->output_len = 0;
#if defined(TYPE_AES_GCM)
        memset(ctx->tag, 0x00, N_AES_TAG_SIZE);
        ctx->tag_len = 0;
#endif
        return AES_SUCCESS;
}

/**
 * @brief       initialize AES key
 * @param       *ctx, *key: key must point to 16-byte memory
 * @return      none
 */
void aes_init_key(struct aes_ctx *ctx, uint8_t *key)
{
        memcpy(ctx->key, key, N_AES_KEY_SIZE);
        aes_key_expansion(ctx->round_key, ctx->key);
}

#if defined(TYPE_AES_CBC)
/**
 * @brief       initialize AES-CBC iv
 * @param       *ctx, *iv: iv must point to 16-byte memory
 * @return      none
 */
void aes_init_iv(struct aes_ctx *ctx, uint8_t *iv)
{
        memcpy(ctx->init_vector, iv, N_AES_STATE_SIZE);
}
#endif

#if defined(TYPE_AES_CTR)
/**
 * @brief       initialize AES-CTR Nonce
 * @param       *ctx, *nonce: nonce must point to 16-byte memory
 * @return      none
 */
void aes_init_nonce(struct aes_ctx *ctx, uint8_t *nonce)
{
        memcpy(ctx->nonce, nonce, N_AES_NONCE_SIZE);
}
#endif

#if defined(TYPE_AES_GCM)
/**
 * @brief       initialize AES-GCM AAD
 * @param       *ctx, *aad, aad_len: aad must point to valid memory
                                        with data size aad_len
 * @return      aes_error:      invalid *aad, for addlen != 0
                                failed malloc for ctx->aad
 */
enum aes_error aes_init_aad(struct aes_ctx *ctx, uint8_t *aad,
                            uint64_t aad_len)
{
        if (aad_len != 0) {
                if (aad == NULL) {
                        return AES_INVALID_INPUT;
                }

                uint8_t *tmp_aad = (uint8_t *)malloc(aad_len);
                if (tmp_aad == NULL) {
                        return AES_MALLOC_FAIL;
                }
                memcpy(tmp_aad, aad, aad_len);
                ctx->aad = tmp_aad;
                ctx->aad_len = aad_len;
        } else {
                ctx->aad = NULL;
                ctx->aad_len = 0;
        }

        return AES_SUCCESS;
}

/**
 * @brief       initialize AES-GCM H
 * @param       *ctx
 * @return      aes_error: if AES-ECB encrypt fail
 */
enum aes_error aes_init_ghash_h(struct aes_ctx *ctx)
{
        uint8_t tmp_zero[16];
        enum aes_error aes_result;
        struct aes_ctx ctx_h;

        memset(tmp_zero, 0x00, 16);

        aes_init_key(&ctx_h, ctx->key);
        ctx_h.input = tmp_zero;
        ctx_h.input_len = 16;
        ctx_h.output = NULL;
        ctx_h.output_len = 0;

        aes_result = aes_ecb_encryption(&ctx_h);

        if (aes_result != AES_SUCCESS) {
                return aes_result;
        }

        memcpy(ctx->ghash_h, ctx_h.output, N_AES_STATE_SIZE);
        free(ctx_h.output);

        return AES_SUCCESS;
}

/**
 * @brief       initialize AES-GCM J0
 * @param       *ctx, *iv, iv_len: iv must point to valid memory
                                        with data size iv_len
 * @return      aes_error:      failed malloc for padded iv
 */
enum aes_error aes_init_j0(struct aes_ctx *ctx, uint8_t *iv, uint64_t iv_len)
{
        if (iv_len == N_AES_IV_SIZE) {
                // 12-byte iv: attach 0x00000001
                memcpy(ctx->j0, iv, iv_len);
                (ctx->j0)[N_AES_IV_SIZE] = 0x00;
                (ctx->j0)[N_AES_IV_SIZE + 1] = 0x00;
                (ctx->j0)[N_AES_IV_SIZE + 2] = 0x00;
                (ctx->j0)[N_AES_IV_SIZE + 3] = 0x01;
        } else {
                uint8_t tmp_j0[16] = {0};
                uint8_t tmp_b[16];

                uint64_t len = (iv_len + 8);
                uint64_t align_len = ((iv_len + 8) + 15) / 16 * 16;

                if (len > 16) {
                        uint64_t end_len = align_len - 16;
                        ghash(ctx->ghash_h, iv, end_len, tmp_j0);

                        if (end_len < iv_len) {
                                // remained iv + padding 0 + len
                                memcpy(tmp_b, iv + end_len, (iv_len - end_len));
                                memset(tmp_b + (iv_len - end_len), 0x00,
                                       (align_len - len));
                                be_set_u64(tmp_b + 8, iv_len * 8);
                        } else {
                                // iv finished in the former blocks.
                                memset(tmp_b, 0x00, 8);
                                be_set_u64(tmp_b + 8, iv_len * 8);
                        }
                        ghash(ctx->ghash_h, tmp_b, 16, tmp_j0);

                } else {
                        // alway use two blocks
                        memcpy(tmp_b, iv, iv_len);
                        memset(tmp_b + iv_len, 0x00, (16 - iv_len));
                        ghash(ctx->ghash_h, tmp_b, 16, tmp_j0);
                        memset(tmp_b, 0x00, 8);
                        be_set_u64(tmp_b + 8, iv_len * 8);
                        ghash(ctx->ghash_h, tmp_b, 16, tmp_j0);
                }

                memcpy(ctx->j0, tmp_j0, 16);
        }

        return AES_SUCCESS;
}

/**
 * @brief       set tag for AES-GCM decryption
 * @param       *ctx, *tag, tag_len: the input tag will be compared
                                        in the range tag_len
 * @return      aes_error:      invalid tag memory
 */
enum aes_error aes_init_tag(struct aes_ctx *ctx, uint8_t *tag,
                            uint8_t tag_len)
{
        if (tag == NULL) {
                return AES_INVALID_INPUT;
        }

        memcpy(ctx->tag, tag, tag_len);
        ctx->tag_len = tag_len;

        return AES_SUCCESS;
}

/**
 * @brief       Generate AES-GCM tag
 * @param       *ctx, *cipher, cipher_len, *tag:
                        get aad, aad_len, key from *ctx
                        generate tag in memory of *tag
 * @return      aes_error:      failed malloc for padded iv
 */
static enum aes_error aes_generate_gmac(struct aes_ctx *ctx, uint8_t *cipher,
                                        size_t cipher_len, uint8_t *tag)
{
        uint8_t tmp_tag[N_AES_TAG_SIZE] = {0};
        uint8_t len_buf[16];

        if (ctx->aad_len > 0) {
                ghash(ctx->ghash_h, ctx->aad, ctx->aad_len, tmp_tag);
        }
        ghash(ctx->ghash_h, cipher, cipher_len, tmp_tag);
        be_set_u64(len_buf, ctx->aad_len * 8);
        be_set_u64(len_buf + 8, cipher_len * 8);
        ghash(ctx->ghash_h, len_buf, sizeof(len_buf), tmp_tag);

        struct aes_ctx ctx_j0;

        aes_init_key(&ctx_j0, ctx->key);
        ctx_j0.input = ctx->j0;
        ctx_j0.input_len = 16;
        ctx_j0.output = NULL;
        ctx_j0.output_len = 0;
        enum aes_error aes_result = aes_ecb_encryption(&ctx_j0);
        if (aes_result != AES_SUCCESS) {
                return aes_result;
        }

        for (uint8_t i = 0; i < N_AES_STATE_SIZE; ++i) {
                tmp_tag[i] ^= ctx_j0.output[i];
        }
        free(ctx_j0.output);

        memcpy(tag, tmp_tag, N_AES_TAG_SIZE);

        return AES_SUCCESS;
}
#endif // TYPE_AES_GCM

#if defined(TYPE_AES_ECB) || defined(TYPE_AES_GCM)
/**
 * @brief       AES-ECB encryption
 * @param       *ctx:   ctx must be a valid object
                        ctx->input must be valid memory
                                with the length ctx->input_len
                        ctx->output should be cleared!
 * @return      aes_error
 */
enum aes_error aes_ecb_encryption(struct aes_ctx *ctx)
{
        if (ctx == NULL) {
                return AES_INVALID_CONTEXT;
        }

        if (ctx->input == NULL || ctx->input_len == 0) {
                return AES_INVALID_INPUT;
        }

        if (ctx->output != NULL || ctx->output_len != 0) {
                return AES_UNCLEARED_OUTPUT;
        }

        // allocate memory for PCKS#7
        uint64_t n_block = (ctx->input_len / N_AES_STATE_SIZE) + 1;
        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint64_t tmp_output_len = ctx->input_len;

        pkcs7_padding(tmp_output, &tmp_output_len, N_AES_STATE_SIZE);

        for (uint64_t b = 0; b < n_block; ++b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);

                aes_step_add_round_key(block, ctx->round_key);

                for (uint8_t r = 0; r < N_AES_ROUND; ++r) {
                        uint8_t round_k = r + 1;

                        aes_step_sub_bytes(block);

                        aes_step_shift_rows(block);

                        if (round_k < N_AES_ROUND) {
                                aes_step_mix_columns(block);
                        }

                        aes_step_add_round_key(
                            block,
                            (ctx->round_key + (round_k * N_AES_STATE_SIZE)));
                }
        }

        ctx->output = tmp_output;
        ctx->output_len = tmp_output_len;

        return AES_SUCCESS;
}
#endif // TYPE_AES_ECB || TYPE_AES_GCM

#if defined(TYPE_AES_ECB)
/**
 * @brief       AES-ECB decryption
 * @param       *ctx:   ctx must be a valid object
                        ctx->input must be valid memory
                                with the length ctx->input_len
                        ctx->output should be cleared!
 * @return      aes_error
 */
enum aes_error aes_ecb_decryption(struct aes_ctx *ctx)
{
        if (ctx == NULL) {
                return AES_INVALID_CONTEXT;
        }

        if (ctx->input == NULL || ctx->input_len == 0) {
                return AES_INVALID_INPUT;
        }

        if (ctx->output != NULL || ctx->output_len != 0) {
                return AES_UNCLEARED_OUTPUT;
        }

        uint64_t n_block = (ctx->input_len / N_AES_STATE_SIZE);
        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint64_t tmp_output_len = ctx->input_len;

        for (uint64_t b = 0; b < n_block; ++b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);

                aes_step_add_round_key(
                    block, (ctx->round_key + (N_AES_ROUND * N_AES_STATE_SIZE)));

                for (uint8_t r = N_AES_ROUND; r > 0; --r) {
                        uint8_t round_k = r - 1;

                        aes_step_inv_shift_rows(block);
                        aes_step_inv_sub_bytes(block);
                        aes_step_add_round_key(
                            block,
                            (ctx->round_key + (round_k * N_AES_STATE_SIZE)));

                        if (round_k > 0) {
                                aes_step_inv_mix_columns(block);
                        }
                }
        }

        pkcs7_unpadding(tmp_output, &tmp_output_len, N_AES_STATE_SIZE);

        ctx->output = tmp_output;
        ctx->output_len = tmp_output_len;

        return AES_SUCCESS;
}
#endif // TYPE_AES_ECB

#if defined(TYPE_AES_CBC)
/**
 * @brief       AES-CBC encryption
 * @param       *ctx:   ctx must be a valid object
                        ctx->input must be valid memory
                                with the length ctx->input_len
                        ctx->output should be cleared!
 * @return      aes_error
 */
enum aes_error aes_cbc_encryption(struct aes_ctx *ctx)
{
        if (ctx == NULL) {
                return AES_INVALID_CONTEXT;
        }

        if (ctx->input == NULL || ctx->input_len == 0) {
                return AES_INVALID_INPUT;
        }

        if (ctx->output != NULL || ctx->output_len != 0) {
                return AES_UNCLEARED_OUTPUT;
        }

        // allocate memory for PCKS#7
        uint64_t n_block = (ctx->input_len / N_AES_STATE_SIZE) + 1;
        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint64_t tmp_output_len = ctx->input_len;

        pkcs7_padding(tmp_output, &tmp_output_len, N_AES_STATE_SIZE);

        for (uint64_t b = 0; b < n_block; ++b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);
                uint8_t *tmp_iv;

                if (b == 0) {
                        tmp_iv = ctx->init_vector;
                } else {
                        tmp_iv = tmp_output + ((b - 1) * N_AES_STATE_SIZE);
                }
                aes_step_cbc_pre_block_xor(block, tmp_iv);

                aes_step_add_round_key(block, ctx->round_key);

                for (uint8_t r = 0; r < N_AES_ROUND; ++r) {
                        uint8_t round_k = r + 1;

                        aes_step_sub_bytes(block);
                        aes_step_shift_rows(block);

                        if (round_k < N_AES_ROUND) {
                                aes_step_mix_columns(block);
                        }

                        aes_step_add_round_key(
                            block,
                            (ctx->round_key + (round_k * N_AES_STATE_SIZE)));
                }
        }

        ctx->output = tmp_output;
        ctx->output_len = tmp_output_len;

        return AES_SUCCESS;
}

/**
 * @brief       AES-CBC decryption
 * @param       *ctx:   ctx must be a valid object
                        ctx->input must be valid memory
                                with the length ctx->input_len
                        ctx->output should be cleared!
 * @return      aes_error
 */
enum aes_error aes_cbc_decryption(struct aes_ctx *ctx)
{
        if (ctx == NULL) {
                return AES_INVALID_CONTEXT;
        }

        if (ctx->input == NULL || ctx->input_len == 0) {
                return AES_INVALID_INPUT;
        }

        if (ctx->output != NULL || ctx->output_len != 0) {
                return AES_UNCLEARED_OUTPUT;
        }

        uint64_t n_block = (ctx->input_len / N_AES_STATE_SIZE);
        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint64_t tmp_output_len = ctx->input_len;

        // AES-CBC: use backward decryption.
        for (int32_t b = (n_block - 1); b >= 0; --b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);
                uint8_t *tmp_iv;

                if (b == 0) {
                        tmp_iv = ctx->init_vector;
                } else {
                        tmp_iv = tmp_output + ((b - 1) * N_AES_STATE_SIZE);
                }

                aes_step_add_round_key(
                    block, (ctx->round_key + (N_AES_ROUND * N_AES_STATE_SIZE)));

                for (uint8_t r = N_AES_ROUND; r > 0; --r) {
                        uint8_t round_k = r - 1;

                        aes_step_inv_shift_rows(block);
                        aes_step_inv_sub_bytes(block);
                        aes_step_add_round_key(
                            block,
                            (ctx->round_key + (round_k * N_AES_STATE_SIZE)));

                        if (round_k > 0) {
                                aes_step_inv_mix_columns(block);
                        }
                }
                aes_step_cbc_pre_block_xor(block, tmp_iv);
        }

        pkcs7_unpadding(tmp_output, &tmp_output_len, N_AES_STATE_SIZE);

        ctx->output = tmp_output;
        ctx->output_len = tmp_output_len;

        return AES_SUCCESS;
}
#endif // TYPE_AES_CBC

#if defined(TYPE_AES_CTR)
/**
 * @brief       AES-CTR encryption
 * @param       *ctx:   ctx must be a valid object
                        ctx->input must be valid memory
                                with the length ctx->input_len
                        ctx->output should be cleared!
 * @return      aes_error
 */
enum aes_error aes_ctr_encryption(struct aes_ctx *ctx)
{
        if (ctx == NULL) {
                return AES_INVALID_CONTEXT;
        }

        if (ctx->input == NULL || ctx->input_len == 0) {
                return AES_INVALID_INPUT;
        }

        if (ctx->output != NULL || ctx->output_len != 0) {
                return AES_UNCLEARED_OUTPUT;
        }

        // use 16-byte aligned memory for XOR operation
        //      although AES-CTR don't need padding plain text
        uint64_t n_block = (ctx->input_len / N_AES_STATE_SIZE) +
                           (ctx->input_len % N_AES_STATE_SIZE == 0 ? 0 : 1);
        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint64_t tmp_output_len = ctx->input_len;
        uint8_t key_stream[N_AES_STATE_SIZE];
        memcpy(key_stream, ctx->nonce, N_AES_NONCE_SIZE);
#if (N_AES_NONCE_SIZE == N_AES_NONCE_NIST)
        // for NIST, 96-bit nonce | 32-bit block_number
        memset(key_stream + N_AES_NONCE_SIZE, 0x00, 4);
#endif

        for (uint64_t b = 0; b < n_block; ++b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);
                uint8_t tmp_key_stream[N_AES_STATE_SIZE];
                memcpy(tmp_key_stream, key_stream, N_AES_NONCE_SIZE);

                aes_step_add_round_key(tmp_key_stream, ctx->round_key);

                for (uint8_t r = 0; r < N_AES_ROUND; ++r) {
                        uint8_t round_k = r + 1;

                        aes_step_sub_bytes(tmp_key_stream);

                        aes_step_shift_rows(tmp_key_stream);

                        if (round_k < N_AES_ROUND) {
                                aes_step_mix_columns(tmp_key_stream);
                        }

                        aes_step_add_round_key(
                            tmp_key_stream,
                            (ctx->round_key + (round_k * N_AES_STATE_SIZE)));
                }

                aes_step_ctr_key_stream_xor(block, tmp_key_stream);
                increment_uint128(key_stream);
        }

        ctx->output = tmp_output;
        ctx->output_len = tmp_output_len;

        return AES_SUCCESS;
}
#endif // TYPE_AES_CTR

#if defined(TYPE_AES_GCM)
/**
 * @brief       AES-GCM encryption
 * @param       *ctx:   ctx must be a valid object
                        ctx->input must be valid memory
                                with the length ctx->input_len
                        ctx->output should be cleared!
 * @return      aes_error
 */
enum aes_error aes_gcm_encryption(struct aes_ctx *ctx)
{
        if (ctx == NULL) {
                return AES_INVALID_CONTEXT;
        }

        if (ctx->input == NULL || ctx->input_len == 0) {
                return AES_INVALID_INPUT;
        }

        if (ctx->output != NULL || ctx->output_len != 0) {
                return AES_UNCLEARED_OUTPUT;
        }

        // use 16-byte aligned memory for XOR operation
        //      although plain text doesn't need padding
        uint64_t n_block = (ctx->input_len / N_AES_STATE_SIZE) +
                           (ctx->input_len % N_AES_STATE_SIZE == 0 ? 0 : 1);

        if (!(n_block < (uint64_t)0xFFFFFFFF)) {
                // AES-GCM: block must less than 2^32-1
                return AES_ILLEGAL_LEN;
        }

        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint64_t tmp_output_len = ctx->input_len;

        uint8_t key_stream[N_AES_STATE_SIZE];
        memcpy(key_stream, ctx->j0, N_AES_STATE_SIZE);

        for (uint64_t b = 0; b < n_block; ++b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);
                uint8_t tmp_key_stream[N_AES_STATE_SIZE];

                increment_uint128(key_stream);
                memcpy(tmp_key_stream, key_stream, N_AES_STATE_SIZE);

                aes_step_add_round_key(tmp_key_stream, ctx->round_key);

                for (uint8_t r = 0; r < N_AES_ROUND; ++r) {
                        uint8_t round_k = r + 1;

                        aes_step_sub_bytes(tmp_key_stream);

                        aes_step_shift_rows(tmp_key_stream);

                        if (round_k < N_AES_ROUND) {
                                aes_step_mix_columns(tmp_key_stream);
                        }

                        aes_step_add_round_key(
                            tmp_key_stream,
                            (ctx->round_key + (round_k * N_AES_STATE_SIZE)));
                }

                aes_step_ctr_key_stream_xor(block, tmp_key_stream);
        }

        ctx->output = tmp_output;
        ctx->output_len = tmp_output_len;

        enum aes_error aes_result =
            aes_generate_gmac(ctx, ctx->output, ctx->output_len, ctx->tag);
        if (aes_result != AES_SUCCESS) {
                return aes_result;
        }
        ctx->tag_len = N_AES_TAG_SIZE;

        return AES_SUCCESS;
}

/**
 * @brief       AES-GCM decryption
 * @param       *ctx:   ctx must be a valid object
                        ctx->input must be valid memory
                                with the length ctx->input_len
                        ctx->output should be cleared!
 * @return      aes_error
 */
enum aes_error aes_gcm_decryption(struct aes_ctx *ctx)
{
        if (ctx == NULL) {
                return AES_INVALID_CONTEXT;
        }

        if (ctx->input == NULL || ctx->input_len == 0) {
                return AES_INVALID_INPUT;
        }

        if (ctx->output != NULL || ctx->output_len != 0) {
                return AES_UNCLEARED_OUTPUT;
        }

        uint8_t tmp_tag[16];
        enum aes_error aes_result =
            aes_generate_gmac(ctx, ctx->input, ctx->input_len, tmp_tag);
        if (aes_result != AES_SUCCESS) {
                return aes_result;
        }

        if (ctx->tag_len <= 16 && ctx->tag_len >= 4) {
                if (memcmp(ctx->tag, tmp_tag, ctx->tag_len) != 0) {
                        return AES_ILLEGAL_TAG;
                }
        } else {
                return AES_INVALID_TAG_INPUT;
        }

        // use 16-byte aligned memory for XOR operation
        //      although plain text doesn't need padding
        uint64_t n_block = (ctx->input_len / N_AES_STATE_SIZE) +
                           (ctx->input_len % N_AES_STATE_SIZE == 0 ? 0 : 1);

        if (!(n_block < (uint64_t)0xFFFFFFFF)) {
                // AES-GCM: block must less than 2^32-1
                return AES_ILLEGAL_LEN;
        }

        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint64_t tmp_output_len = ctx->input_len;

        uint8_t key_stream[N_AES_STATE_SIZE];
        memcpy(key_stream, ctx->j0, N_AES_STATE_SIZE);

        for (uint64_t b = 0; b < n_block; ++b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);
                uint8_t tmp_key_stream[N_AES_STATE_SIZE];

                increment_uint128(key_stream);
                memcpy(tmp_key_stream, key_stream, N_AES_STATE_SIZE);

                aes_step_add_round_key(tmp_key_stream, ctx->round_key);

                for (uint8_t r = 0; r < N_AES_ROUND; ++r) {
                        uint8_t round_k = r + 1;

                        aes_step_sub_bytes(tmp_key_stream);

                        aes_step_shift_rows(tmp_key_stream);

                        if (round_k < N_AES_ROUND) {
                                aes_step_mix_columns(tmp_key_stream);
                        }

                        aes_step_add_round_key(
                            tmp_key_stream,
                            (ctx->round_key + (round_k * N_AES_STATE_SIZE)));
                }

                aes_step_ctr_key_stream_xor(block, tmp_key_stream);
        }

        ctx->output = tmp_output;
        ctx->output_len = tmp_output_len;

        return AES_SUCCESS;
}
#endif // TYPE_AES_GCM

/**
 * @brief       Expand AES key into round_key
 * @param round_key     Output buffer of expanded keys
 * @param key           Original key (must be initialized)
 */
static void aes_key_expansion(uint8_t *round_key, const uint8_t *key)
{
        int word_idx, ref_idx;
        uint8_t tmp[4];

        memcpy(round_key, key, N_AES_KEY_SIZE);

        for (word_idx = N_AES_KEY_SIZE; word_idx < N_AES_KEY_EXPAND_SIZE;
             word_idx += 4) {
                ref_idx = (word_idx - 4);

                tmp[0] = round_key[ref_idx];
                tmp[1] = round_key[(ref_idx + 1)];
                tmp[2] = round_key[(ref_idx + 2)];
                tmp[3] = round_key[(ref_idx + 3)];

                if (word_idx % N_AES_KEY_SIZE == 0) {
                        const uint8_t u8tmp = tmp[0];
                        tmp[0] = tmp[1];
                        tmp[1] = tmp[2];
                        tmp[2] = tmp[3];
                        tmp[3] = u8tmp;

                        tmp[0] = rijndael_s_box[tmp[0]];
                        tmp[1] = rijndael_s_box[tmp[1]];
                        tmp[2] = rijndael_s_box[tmp[2]];
                        tmp[3] = rijndael_s_box[tmp[3]];

                        tmp[0] ^= rijndael_r_con[(word_idx / N_AES_KEY_SIZE)];
                }
#if defined(ALGO_AES_256)
                else if (word_idx % N_AES_KEY_SIZE == (N_AES_KEY_SIZE / 2)) {
                        tmp[0] = rijndael_s_box[tmp[0]];
                        tmp[1] = rijndael_s_box[tmp[1]];
                        tmp[2] = rijndael_s_box[tmp[2]];
                        tmp[3] = rijndael_s_box[tmp[3]];
                }
#endif

                ref_idx = (word_idx - N_AES_KEY_SIZE);
                round_key[word_idx] = round_key[ref_idx] ^ tmp[0];
                round_key[(word_idx + 1)] = round_key[(ref_idx + 1)] ^ tmp[1];
                round_key[(word_idx + 2)] = round_key[(ref_idx + 2)] ^ tmp[2];
                round_key[(word_idx + 3)] = round_key[(ref_idx + 3)] ^ tmp[3];
        }
}

#if defined(TYPE_AES_CBC)
static void aes_step_cbc_pre_block_xor(uint8_t *state, uint8_t *vector)
{
        uint8_t i;
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                state[i] ^= vector[i];
        }
}
#endif // TYPE_AES_CBC

#if defined(TYPE_AES_CTR) || defined(TYPE_AES_GCM)
static void aes_step_ctr_key_stream_xor(uint8_t *state, uint8_t *key_stream)
{
        uint8_t i;
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                state[i] ^= key_stream[i];
        }
}
#endif // TYPE_AES_CTR || TYPE_AES_GCM

static void aes_step_sub_bytes(uint8_t *state)
{
        uint8_t i;
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                state[i] = rijndael_s_box[state[i]];
        }
}

static void aes_step_shift_rows(uint8_t *state)
{
        uint8_t u8tmp;

        u8tmp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = u8tmp;

        u8tmp = state[2];
        state[2] = state[10];
        state[10] = u8tmp;
        u8tmp = state[6];
        state[6] = state[14];
        state[14] = u8tmp;

        u8tmp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = u8tmp;
}

static void aes_step_mix_columns(uint8_t *state)
{
        uint8_t tmp[4];
        /*
        2 3 1 1
        1 2 3 1
        1 1 2 3
        3 1 1 2
        */
        uint8_t col_idx, offset;

        for (col_idx = 0; col_idx < 4; ++col_idx) {
                offset = (col_idx * 4);
                tmp[0] = state[offset];
                tmp[1] = state[(offset + 1)];
                tmp[2] = state[(offset + 2)];
                tmp[3] = state[(offset + 3)];

                state[offset] = gf8_multiply(0x02, tmp[0]) ^
                                gf8_multiply(0x03, tmp[1]) ^ tmp[2] ^ tmp[3];
                state[(offset + 1)] = tmp[0] ^ gf8_multiply(0x02, tmp[1]) ^
                                      gf8_multiply(0x03, tmp[2]) ^ tmp[3];
                state[(offset + 2)] = tmp[0] ^ tmp[1] ^
                                      gf8_multiply(0x02, tmp[2]) ^
                                      gf8_multiply(0x03, tmp[3]);
                state[(offset + 3)] = gf8_multiply(0x03, tmp[0]) ^ tmp[1] ^
                                      tmp[2] ^ gf8_multiply(0x02, tmp[3]);
        }
}

static void aes_step_add_round_key(uint8_t *state, uint8_t *round_key)
{
        uint8_t i;

        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                state[i] ^= round_key[i];
        }
}

#if (!defined(TYPE_AES_CTR) && !defined(TYPE_AES_GCM))
static void aes_step_inv_sub_bytes(uint8_t *state)
{
        uint8_t i;
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                state[i] = rijndael_inverse_s_box[state[i]];
        }
}

static void aes_step_inv_shift_rows(uint8_t *state)
{
        uint8_t u8tmp;

        u8tmp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = u8tmp;

        u8tmp = state[2];
        state[2] = state[10];
        state[10] = u8tmp;
        u8tmp = state[6];
        state[6] = state[14];
        state[14] = u8tmp;

        u8tmp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = u8tmp;
}

static void aes_step_inv_mix_columns(uint8_t *state)
{
        uint8_t tmp[4];
        /*
        E B D 9
        9 E B D
        D 9 E B
        B D 9 E
        */
        uint8_t col_idx, offset;

        for (col_idx = 0; col_idx < 4; ++col_idx) {
                offset = (col_idx * 4);
                tmp[0] = *(state + offset);
                tmp[1] = *(state + offset + 1);
                tmp[2] = *(state + offset + 2);
                tmp[3] = *(state + offset + 3);

                *(state + offset) =
                    gf8_multiply(0x0e, tmp[0]) ^ gf8_multiply(0x0b, tmp[1]) ^
                    gf8_multiply(0x0d, tmp[2]) ^ gf8_multiply(0x09, tmp[3]);
                *(state + offset + 1) =
                    gf8_multiply(0x09, tmp[0]) ^ gf8_multiply(0x0e, tmp[1]) ^
                    gf8_multiply(0x0b, tmp[2]) ^ gf8_multiply(0x0d, tmp[3]);
                *(state + offset + 2) =
                    gf8_multiply(0x0d, tmp[0]) ^ gf8_multiply(0x09, tmp[1]) ^
                    gf8_multiply(0x0e, tmp[2]) ^ gf8_multiply(0x0b, tmp[3]);
                *(state + offset + 3) =
                    gf8_multiply(0x0b, tmp[0]) ^ gf8_multiply(0x0d, tmp[1]) ^
                    gf8_multiply(0x09, tmp[2]) ^ gf8_multiply(0x0e, tmp[3]);
        }
}
#endif // !TYPE_AES_CTR

// Galois Field multiply
static uint8_t gf8_multiply(uint8_t a, uint8_t b)
{
        uint8_t res = 0;

        for (uint8_t bit_idx = 0; bit_idx < 8; ++bit_idx) {
                if (b & 1) {
                        res ^= a;
                }
                a = (a & 0x80 ? 0x1b : 0) ^ (a << 1);
                b >>= 1;
        }

        return res;
}

#if defined(TYPE_AES_GCM)

static void be_set_u64(uint8_t *x, uint64_t val)
{
        for (uint8_t i = 0; i < 8; ++i) {
                x[i] = (val >> (7 - i) * 8) & 0xff;
        }
}

static void be_set_u32(uint8_t *x, uint32_t val)
{
        for (uint8_t i = 0; i < 4; ++i) {
                x[i] = (val >> (3 - i) * 8) & 0xff;
        }
}

static inline uint32_t be_get_u32(const uint8_t *x)
{
        return (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3];
}

static void gf128_right_shift(uint8_t *v)
{
        uint32_t val;

        for (int i = 0; i < 4; ++i) {
                int offset = (3 - i) * 4;
                val = be_get_u32(v + offset);
                val >>= 1;
                if (offset) {
                        if (v[(offset - 1)] & 0x01) {
                                val |= 0x80000000;
                        }
                }
                be_set_u32(v + offset, val);
        }
}

static void gf128_multiply(uint8_t *x, uint8_t *y, uint8_t *z)
{
        uint8_t v[16];

        memset(z, 0, 16);
        memcpy(v, y, 16);

        // GF(2^128) = x^128 + x^7 + x^2 + x + 1
        for (int byte_idx = 0; byte_idx < 16; byte_idx++) {
                for (uint8_t bit_idx = 0; bit_idx < 8; bit_idx++) {
                        if (x[byte_idx] & 1 << (7 - bit_idx)) {
                                // bit == 1, z^=y
                                for (uint8_t k = 0; k < 16; k++) {
                                        z[k] ^= v[k];
                                }
                        }

                        uint8_t carry = (v[15] & 0x01) ? 1 : 0;

                        gf128_right_shift(v);

                        if (carry) {
                                // handle the carry bit, 0x87<<1 = 0xe1
                                v[0] ^= 0xe1;
                        }
                }
        }
}

static void ghash(uint8_t *h, uint8_t *data, size_t data_len, uint8_t *y)
{
        uint8_t *ptr_data = data;
        uint8_t tmp[16];

        size_t n_block = data_len / 16;

        for (size_t i = 0; i < n_block; ++i) {
                // XOR
                for (uint8_t j = 0; j < 16; j++) {
                        y[j] ^= ptr_data[j];
                }

                // GF(2^128) multiplication
                gf128_multiply(y, h, tmp);
                memcpy(y, tmp, 16);

                ptr_data += 16;
        }

        // padding 0 for 16-byte aligned
        if (data + data_len > ptr_data) {
                size_t rest = data + data_len - ptr_data;
                memcpy(tmp, ptr_data, rest);
                memset(tmp + rest, 0x00, sizeof(tmp) - rest);

                // XOR
                for (uint8_t j = 0; j < 16; j++) {
                        y[j] ^= tmp[j];
                }

                // GF(2^128) multiplication
                gf128_multiply(y, h, tmp);
                memcpy(y, tmp, 16);
        }
}
#endif // TYPE_AES_GCM
#if defined(TYPE_AES_GCM) || defined(TYPE_AES_CTR)
static void increment_uint128(uint8_t *bytes)
{
        uint8_t carry = 1;
        for (int i = 15; i >= 0 && carry != 0; --i) {
                if (bytes[i] == 0xFF) {
                        bytes[i] = 0x00;
                } else {
                        bytes[i] += carry;
                        carry = 0;
                }
        }
}
#endif
