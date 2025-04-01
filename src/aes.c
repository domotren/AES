
#include "aes.h"

const uint8_t rijndael_r_con[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                    0x20, 0x40, 0x80, 0x1b, 0x36};

static void aes_key_expansion(uint8_t *round_key, const uint8_t *key);
#if defined(TYPE_AES_CBC)
static void aes_step_cbc_pre_block_xor(uint8_t *state, uint8_t *vector);
#endif
#if defined(TYPE_AES_CTR)
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
static uint8_t gf_multiply_8(uint8_t a, uint8_t b);
#if defined(TYPE_AES_GCM)
static void gf_multiply_128(uint8_t *a, uint8_t *b);
static void ghash(uint8_t *H, uint8_t *data, uint32_t len, uint8_t *output);
#endif
#if defined(TYPE_AES_GCM) || defined(TYPE_AES_CTR)
static void increment_uint128(uint8_t *bytes);
#endif

/**
 * @brief       initialize AES key
 * @param       *ctx, *key: key must point to 16-byte memory
 * @return      none
 */
void aes_key_init(struct aes_ctx *ctx, uint8_t *key)
{
        memcpy(ctx->aes_key, key, N_AES_KEY_SIZE);
        aes_key_expansion(ctx->aes_round_key, ctx->aes_key);
}

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

        memset(ctx->aes_key, 0x00, N_AES_KEY_SIZE);
        memset(ctx->aes_round_key, 0x00, N_AES_KEY_EXPAND_SIZE);
#if defined(TYPE_AES_CBC)
        memset(ctx->aes_init_vector, 0x00, N_AES_KEY_SIZE);
#endif
        free(ctx->input);
        ctx->input_len = 0;
        free(ctx->output);
        ctx->output_len = 0;

        return AES_SUCCESS;
}

#if defined(TYPE_AES_CBC)
/**
 * @brief       initialize AES-CBC iv
 * @param       *ctx, *iv: iv must point to 16-byte memory
 * @return      none
 */
void aes_iv_init(struct aes_ctx *ctx, uint8_t *iv)
{
        memcpy(ctx->aes_init_vector, iv, N_AES_KEY_SIZE);
}
#endif

#if defined(TYPE_AES_CTR)
/**
 * @brief       initialize AES-CTR Nonce
 * @param       *ctx, *nonce: nonce must point to 16-byte memory
 * @return      none
 */
void aes_nonce_init(struct aes_ctx *ctx, uint8_t *nonce)
{
        memcpy(ctx->aes_nonce, nonce, N_AES_NONCE_SIZE);
}
#endif

#if defined(TYPE_AES_GCM)
void aes_ghash_h_init(void)
{
        uint8_t tmp_zero[16] = {0};
        uint8_t cipher_size = 16;
        uint8_t *cipher;
        cipher = aes_ecb_encryption(tmp_zero, N_AES_STATE_SIZE, &cipher_size);
        memcpy(aes_ghash_h, cipher, N_AES_STATE_SIZE);
        free(cipher);
}

void aes_j0_init(uint8_t *iv, uint32_t iv_size)
{
        if (iv_size == N_AES_IV_SIZE) {
                // 12-byte iv: attach 0x00000001
                memcpy(aes_j0, iv, iv_size);
                aes_j0[N_AES_IV_SIZE] = 0x00;
                aes_j0[N_AES_IV_SIZE + 1] = 0x00;
                aes_j0[N_AES_IV_SIZE + 2] = 0x00;
                aes_j0[N_AES_IV_SIZE + 3] = 0x01;
        } else {
                // padding as multiples of 16-byte, 
                //      and attach 8-byte iv bits by Big-endian
                
                uint32_t n_padded = ((iv_size + 15) / 16) * 16;
                uint32_t n_total = n_padded + 8;
                uint8_t *ptr_iv = (uint8_t *)malloc(n_total);

                memcpy(ptr_iv, iv, iv_size);
                memset(ptr_iv + iv_size, 0x00, (n_padded - iv_size));
                uint64_t iv_bit = (uint64_t)iv_size * 8;

                for (uint32_t i = 0; i < 8; ++i) {
                        ptr_iv[n_padded + i] = (iv_bit >> (56 - i * 8)) & 0xFF;
                }

                ghash(aes_ghash_h, ptr_iv, n_total, aes_j0);
                free(ptr_iv);
        }
}

static uint8_t *aes_generate_gmac(uint8_t *aad, uint32_t aad_len,
                                  uint8_t *cipher, uint32_t cipher_len)
{
        uint8_t *tmp;
        uint32_t tmp_len;
        uint32_t pad_aad_len, pad_cipher_len;

        if (aad == NULL || cipher == NULL) {
                // invalid input memory
                return NULL;
        }

        if (aad_len > 0) {
                pad_aad_len = ((aad_len + 15) / 16) * 16;
        } else {
                pad_aad_len = 0;
        }
        pad_cipher_len = ((cipher_len + 15) / 16) * 16;

        tmp_len = pad_aad_len + pad_cipher_len + 8 + 8;
        tmp = (uint8_t *)malloc(tmp_len);

        if (tmp == NULL) {
                // failed to alloc tmp
                return NULL;
        }

        if (pad_aad_len > 0) {
                memcpy(tmp, aad, aad_len);
                memset(tmp + aad_len, 0x00, pad_aad_len - aad_len);
        }
        memcpy(tmp + pad_aad_len, cipher, cipher_len);
        memset(tmp + pad_aad_len + cipher_len, 0x00, pad_cipher_len - cipher_len);

        uint64_t aad_bit = (uint64_t)aad_len * 8;
        uint64_t cipher_bit = (uint64_t)cipher_len * 8;

        memcpy(tmp + pad_aad_len + cipher_len, &aad_bit, 8);
        memcpy(tmp + pad_aad_len + cipher_len + 8, &cipher_bit, 8);

        uint8_t tmp_ghash[16];
        uint8_t *cipher_j0;
        uint32_t cipher_j0_size;
        uint8_t *tag = (uint8_t *)malloc(16);
        
        if (tag == NULL) {
                /// failed to alloc tag
                free(tmp);
                return NULL;
        }

        ghash(aes_ghash_h, tmp, tmp_len, tmp_ghash);
        cipher_j0 = *aes_ecb_encryption(aes_j0, 16, &cipher_j0_size);

        if (cipher_j0 == NULL) {
                // failed to encrpt J0
                free(tmp);
                free(tag);
                return NULL;
        }

        memcpy(tag, tmp_ghash, 16);
        for (uint8_t i = 0; i < N_AES_STATE_SIZE; ++i) {
                tag[i] ^= cipher_j0[i];
        }
        
        free(tmp);
        free(cipher_j0);
        return tag;
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

        // output memory should not exist
        if (ctx->output != NULL || ctx->output_len != 0) {
                free(ctx->output);
                ctx->output_len = 0;
        }

        // allocate memory for PCKS#7
        uint32_t n_block = (ctx->input_len / N_AES_STATE_SIZE) + 1;
        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint32_t tmp_output_len = ctx->input_len;

        pkcs7_padding(tmp_output, &tmp_output_len, N_AES_STATE_SIZE);

        for (uint32_t b = 0; b < n_block; ++b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);

                aes_step_add_round_key(block, ctx->aes_round_key);

                for (uint8_t r = 0; r < N_AES_ROUND; ++r) {
                        uint8_t round_k = r + 1;

                        aes_step_sub_bytes(block);

                        aes_step_shift_rows(block);

                        if (round_k < N_AES_ROUND) {
                                aes_step_mix_columns(block);
                        }

                        aes_step_add_round_key(
                            block,
                            (ctx->aes_round_key + (round_k * N_AES_KEY_SIZE)));
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

        // output memory should not exist
        if (ctx->output != NULL || ctx->output_len != 0) {
                free(ctx->output);
                ctx->output_len = 0;
        }

        uint32_t n_block = (ctx->input_len / N_AES_STATE_SIZE);
        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint32_t tmp_output_len = ctx->input_len;

        for (uint32_t b = 0; b < n_block; ++b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);

                aes_step_add_round_key(
                    block,
                    (ctx->aes_round_key + (N_AES_ROUND * N_AES_KEY_SIZE)));

                for (uint8_t r = N_AES_ROUND; r > 0; --r) {
                        uint8_t round_k = r - 1;

                        aes_step_inv_shift_rows(block);
                        aes_step_inv_sub_bytes(block);
                        aes_step_add_round_key(
                            block,
                            (ctx->aes_round_key + (round_k * N_AES_KEY_SIZE)));

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

        // output memory should not exist
        if (ctx->output != NULL || ctx->output_len != 0) {
                free(ctx->output);
                ctx->output_len = 0;
        }

        // allocate memory for PCKS#7
        uint32_t n_block = (ctx->input_len / N_AES_STATE_SIZE) + 1;
        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint32_t tmp_output_len = ctx->input_len;

        pkcs7_padding(tmp_output, &tmp_output_len, N_AES_STATE_SIZE);

        for (uint32_t b = 0; b < n_block; ++b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);
                uint8_t *tmp_iv;

                if (b == 0) {
                        tmp_iv = ctx->aes_init_vector;
                } else {
                        tmp_iv = tmp_output + ((b - 1) * N_AES_STATE_SIZE);
                }
                aes_step_cbc_pre_block_xor(block, tmp_iv);

                aes_step_add_round_key(block, ctx->aes_round_key);

                for (uint8_t r = 0; r < N_AES_ROUND; ++r) {
                        uint8_t round_k = r + 1;

                        aes_step_sub_bytes(block);
                        aes_step_shift_rows(block);

                        if (round_k < N_AES_ROUND) {
                                aes_step_mix_columns(block);
                        }

                        aes_step_add_round_key(
                            block,
                            (ctx->aes_round_key + (round_k * N_AES_KEY_SIZE)));
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

        // output memory should not exist
        if (ctx->output != NULL || ctx->output_len != 0) {
                free(ctx->output);
                ctx->output_len = 0;
        }

        uint32_t n_block = (ctx->input_len / N_AES_STATE_SIZE);
        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));
        
        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint32_t tmp_output_len = ctx->input_len;

        // AES-CBC: use backward decryption.
        for (int32_t b = (n_block - 1); b >= 0; --b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);
                uint8_t *tmp_iv;

                if (b == 0) {
                        tmp_iv = ctx->aes_init_vector;
                } else {
                        tmp_iv = tmp_output + ((b - 1) * N_AES_STATE_SIZE);
                }

                aes_step_add_round_key(
                    block,
                    (ctx->aes_round_key + (N_AES_ROUND * N_AES_KEY_SIZE)));

                for (uint8_t r = N_AES_ROUND; r > 0; --r) {
                        uint8_t round_k = r - 1;

                        aes_step_inv_shift_rows(block);
                        aes_step_inv_sub_bytes(block);
                        aes_step_add_round_key(
                            block,
                            (ctx->aes_round_key + (round_k * N_AES_KEY_SIZE)));

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

        // output memory should not exist
        if (ctx->output != NULL || ctx->output_len != 0) {
                free(ctx->output);
                ctx->output_len = 0;
        }

        // use 16-byte aligned memory for XOR operation
        //      although AES-CTR don't need padding plain text
        uint32_t n_block = (ctx->input_len / N_AES_STATE_SIZE) +
                           (ctx->input_len % N_AES_STATE_SIZE == 0 ? 0 : 1);
        uint8_t *tmp_output = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        if (tmp_output == NULL) {
                return AES_MALLOC_FAIL;
        }

        memcpy(tmp_output, ctx->input, ctx->input_len);
        uint32_t tmp_output_len = ctx->input_len;
        uint8_t key_stream[N_AES_STATE_SIZE];
        memcpy(key_stream, ctx->aes_nonce, N_AES_NONCE_SIZE);
#if (N_AES_NONCE_SIZE == N_AES_NONCE_NIST)
        // for NIST, 96-bit nonce | 32-bit block_number
        memset(key_stream + N_AES_NONCE_SIZE, 0x00, 4);
#endif

        for (uint32_t b = 0; b < n_block; ++b) {
                uint8_t *block = tmp_output + (b * N_AES_STATE_SIZE);

                aes_step_add_round_key(key_stream, ctx->aes_round_key);

                for (uint8_t r = 0; r < N_AES_ROUND; ++r) {
                        uint8_t round_k = r + 1;

                        aes_step_sub_bytes(key_stream);

                        aes_step_shift_rows(key_stream);

                        if (round_k < N_AES_ROUND) {
                                aes_step_mix_columns(key_stream);
                        }

                        aes_step_add_round_key(
                            key_stream,
                            (ctx->aes_round_key + (round_k * N_AES_KEY_SIZE)));
                }

                aes_step_ctr_key_stream_xor(block, key_stream);

                increment_uint128(key_stream);
        }

        ctx->output = tmp_output;
        ctx->output_len = tmp_output_len;

        return AES_SUCCESS;
}
#endif // TYPE_AES_CTR


static void aes_key_expansion(uint8_t *round_key, const uint8_t *key)
{
        uint8_t word_idx, ref_idx;
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

#if defined(TYPE_AES_CTR)
static void aes_step_ctr_key_stream_xor(uint8_t *state, uint8_t *key_stream)
{
        uint8_t i;
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                state[i] ^= key_stream[i];
        }
}
#endif // TYPE_AES_CTR

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

                state[offset] = gf_multiply_8(0x02, tmp[0]) ^
                                gf_multiply_8(0x03, tmp[1]) ^ tmp[2] ^ tmp[3];
                state[(offset + 1)] = tmp[0] ^ gf_multiply_8(0x02, tmp[1]) ^
                                      gf_multiply_8(0x03, tmp[2]) ^ tmp[3];
                state[(offset + 2)] = tmp[0] ^ tmp[1] ^
                                      gf_multiply_8(0x02, tmp[2]) ^
                                      gf_multiply_8(0x03, tmp[3]);
                state[(offset + 3)] = gf_multiply_8(0x03, tmp[0]) ^ tmp[1] ^
                                      tmp[2] ^ gf_multiply_8(0x02, tmp[3]);
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
                    gf_multiply_8(0x0e, tmp[0]) ^ gf_multiply_8(0x0b, tmp[1]) ^
                    gf_multiply_8(0x0d, tmp[2]) ^ gf_multiply_8(0x09, tmp[3]);
                *(state + offset + 1) =
                    gf_multiply_8(0x09, tmp[0]) ^ gf_multiply_8(0x0e, tmp[1]) ^
                    gf_multiply_8(0x0b, tmp[2]) ^ gf_multiply_8(0x0d, tmp[3]);
                *(state + offset + 2) =
                    gf_multiply_8(0x0d, tmp[0]) ^ gf_multiply_8(0x09, tmp[1]) ^
                    gf_multiply_8(0x0e, tmp[2]) ^ gf_multiply_8(0x0b, tmp[3]);
                *(state + offset + 3) =
                    gf_multiply_8(0x0b, tmp[0]) ^ gf_multiply_8(0x0d, tmp[1]) ^
                    gf_multiply_8(0x09, tmp[2]) ^ gf_multiply_8(0x0e, tmp[3]);
        }
}
#endif // !TYPE_AES_CTR

// Galois Field multiply
static uint8_t gf_multiply_8(uint8_t a, uint8_t b)
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
static void gf_multiply_128(uint8_t *a, uint8_t *b)
{
        uint8_t res[16] = {0};
        uint8_t tmp[16];
        memcpy(tmp, b, 16);

        for (uint8_t bit_idx = 0; bit_idx < 128; ++bit_idx) {
                if (a[15] & 0x80) {
                    for (uint8_t i = 0; i < 16; ++i) {
                        res[i] ^= tmp[i];
                    }
                }

                uint8_t carry = (tmp[15] & 0x01) ? 0xE1 : 0x00;
                for (uint8_t i = 15; i > 0; --i) {
                    tmp[i] = (tmp[i] >> 1) | ((tmp[i-1] & 0x01) << 7);
                }
                tmp[0] = (tmp[0] >> 1) ^ carry;

                for (uint8_t i = 15; i > 0; --i) {
                    a[i] = (a[i] << 1) | ((a[i-1] & 0x80) >> 7);
                }
                a[0] <<= 1;
        }
        memcpy(a, res, 16);
}

static void ghash(uint8_t *H, uint8_t *data, uint32_t len, uint8_t *output)
{
    uint8_t a[16] = {0};
    for (uint32_t i = 0; i < len; i += 16) {
        for (uint8_t j = 0; j < 16; ++j) {
            a[j] ^= data[i + j];
        }

        gf_multiply_128(a, H);
    }
    memcpy(output, a, 16);
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
