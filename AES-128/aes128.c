
#include "aes128.h"

const uint8_t rijndael_r_con[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                    0x20, 0x40, 0x80, 0x1b, 0x36};

static uint8_t aes_round_key[N_AES_KEY_EXPAND_SIZE];
#if defined(TYPE_AES_CBC)
static uint8_t aes_init_vector[N_AES_STATE_SIZE];
#endif

// Galois Field multiply
static uint8_t gf_multiply(uint8_t a, uint8_t b)
{
        uint8_t res = 0;
        uint8_t bit_idx;
        for (bit_idx = 0; bit_idx < 8; ++bit_idx) {
                if (b & 1) {
                        res ^= a;
                }
                a = (a & 0x80 ? 0x1b : 0) ^ (a << 1);
                b >>= 1;
        }

        return res;
}

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

                state[offset] = gf_multiply(0x02, tmp[0]) ^
                                gf_multiply(0x03, tmp[1]) ^ tmp[2] ^ tmp[3];
                state[(offset + 1)] = tmp[0] ^ gf_multiply(0x02, tmp[1]) ^
                                      gf_multiply(0x03, tmp[2]) ^ tmp[3];
                state[(offset + 2)] = tmp[0] ^ tmp[1] ^
                                      gf_multiply(0x02, tmp[2]) ^
                                      gf_multiply(0x03, tmp[3]);
                state[(offset + 3)] = gf_multiply(0x03, tmp[0]) ^ tmp[1] ^
                                      tmp[2] ^ gf_multiply(0x02, tmp[3]);
        }
}

static void aes_step_add_round_key(uint8_t *state, uint8_t *round_key)
{
        uint8_t i;

        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                state[i] ^= round_key[i];
        }
}

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
                    gf_multiply(0x0e, tmp[0]) ^ gf_multiply(0x0b, tmp[1]) ^
                    gf_multiply(0x0d, tmp[2]) ^ gf_multiply(0x09, tmp[3]);
                *(state + offset + 1) =
                    gf_multiply(0x09, tmp[0]) ^ gf_multiply(0x0e, tmp[1]) ^
                    gf_multiply(0x0b, tmp[2]) ^ gf_multiply(0x0d, tmp[3]);
                *(state + offset + 2) =
                    gf_multiply(0x0d, tmp[0]) ^ gf_multiply(0x09, tmp[1]) ^
                    gf_multiply(0x0e, tmp[2]) ^ gf_multiply(0x0b, tmp[3]);
                *(state + offset + 3) =
                    gf_multiply(0x0b, tmp[0]) ^ gf_multiply(0x0d, tmp[1]) ^
                    gf_multiply(0x09, tmp[2]) ^ gf_multiply(0x0e, tmp[3]);
        }
}

void aes_key_init(uint8_t *key)
{
        aes_key_expansion(aes_round_key, key);
}

#if defined(TYPE_AES_CBC)
void aes_iv_init(uint8_t *init_vector)
{
        memcpy(aes_init_vector, init_vector, N_AES_STATE_SIZE);
}
#endif

uint8_t *aes_encryption(uint8_t *plain, uint32_t plain_size,
                        uint32_t *cipher_size)
{
#if defined(TYPE_AES_CBC)
        uint8_t *init_vector;
#endif
        uint32_t n_block;

        uint8_t *cipher;

        if (plain == NULL) {
                *cipher_size = 0;
                return NULL;
        }

        n_block = (plain_size / N_AES_STATE_SIZE) + 1;
        cipher = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        memcpy(cipher, plain, plain_size);
        *cipher_size = plain_size;

        pkcs7_padding(cipher, cipher_size, N_AES_STATE_SIZE);

        for (uint32_t block_idx = 0; block_idx < n_block; ++block_idx) {
                uint32_t text_offset = block_idx * N_AES_STATE_SIZE;

#if defined(TYPE_AES_CBC)
                if (block_idx == 0) {
                        init_vector = aes_init_vector;
                } else {
                        init_vector =
                            cipher + (block_idx - 1) * N_AES_STATE_SIZE;
                }
                aes_step_cbc_pre_block_xor(cipher + text_offset, init_vector);
#endif

                aes_step_add_round_key(cipher + text_offset, aes_round_key);

                for (uint8_t round_idx = 0; round_idx < N_AES_ROUND;
                     ++round_idx) {
                        uint8_t current_round = round_idx + 1;

                        aes_step_sub_bytes(cipher + text_offset);

                        aes_step_shift_rows(cipher + text_offset);

                        if (current_round < N_AES_ROUND) {
                                aes_step_mix_columns(cipher + text_offset);
                        }

                        aes_step_add_round_key(
                            cipher + text_offset,
                            (aes_round_key + (current_round * N_AES_KEY_SIZE)));
                }
        }

        return cipher;
}

uint8_t *aes_decryption(uint8_t *cipher, uint32_t cipher_size,
                        uint32_t *plain_size)
{
#if defined(TYPE_AES_CBC)
        uint8_t *init_vector;
#endif
        uint32_t n_block;
        uint8_t *plain;

        if (cipher == NULL) {
                *plain_size = 0;
                return NULL;
        }

        n_block = (cipher_size / N_AES_STATE_SIZE);
        plain = (uint8_t *)malloc((n_block * N_AES_STATE_SIZE));

        memcpy(plain, cipher, cipher_size);
        *plain_size = cipher_size;

#if defined(TYPE_AES_CBC)
        // backward decryption for CBC mode
        for (int32_t block_idx = (n_block - 1); block_idx >= 0; --block_idx) {
#else
        for (uint32_t block_idx = 0; block_idx < n_block; ++block_idx) {
#endif
                uint32_t text_offset = block_idx * N_AES_STATE_SIZE;

#if defined(TYPE_AES_CBC)
                if (block_idx == 0) {
                        init_vector = aes_init_vector;
                } else {
                        init_vector =
                            cipher + (block_idx - 1) * N_AES_STATE_SIZE;
                }
#endif

                aes_step_add_round_key(
                    plain + text_offset,
                    (aes_round_key + (N_AES_ROUND * N_AES_KEY_SIZE)));

                for (uint8_t round_idx = N_AES_ROUND; round_idx > 0;
                     --round_idx) {
                        uint8_t current_round = round_idx - 1;

                        aes_step_inv_shift_rows(plain + text_offset);
                        aes_step_inv_sub_bytes(plain + text_offset);
                        aes_step_add_round_key(
                            plain + text_offset,
                            (aes_round_key + (current_round * N_AES_KEY_SIZE)));

                        if (current_round > 0) {
                                aes_step_inv_mix_columns(plain + text_offset);
                        }
                }

#if defined(TYPE_AES_CBC)
                aes_step_cbc_pre_block_xor(plain + text_offset, init_vector);
#endif
        }

        pkcs7_unpadding(plain, plain_size, N_AES_STATE_SIZE);
        return plain;
}
