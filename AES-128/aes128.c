
#include "aes128.h"

const uint8_t rijndael_r_con[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                    0x20, 0x40, 0x80, 0x1b, 0x36};

static uint8_t aes_round_key[N_AES_KEY_EXPAND_SIZE];

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

#if defined(FEATURE_PKCS7_ENABLE)

static void pkcs7_padding(uint8_t *data, uint8_t *data_size,
                          uint8_t block_size)
{
        uint8_t padding_size = block_size - *data_size;
        memset((data + *data_size), padding_size, padding_size);
        *data_size = block_size;
}

static void pkcs7_unpadding(uint8_t *data, uint8_t *data_size,
                            uint8_t block_size)
{
        uint8_t final_data = *(data + block_size - 1);
        uint8_t i;

        if ((final_data == 0x00) || (final_data > block_size)) {
                return;
        }

        for (i = 0; i < final_data; ++i) {
                if (*(data + block_size - 1 - i) != final_data) {
                        return;
                }
        }

        *data_size = (block_size - final_data);
}

#endif // FEATURE_PKCS7_ENABLE

void aes_init(uint8_t *key)
{
        aes_key_expansion(aes_round_key, key);
}

void aes_encryption(uint8_t *plain_text, uint8_t *output)
{
        uint8_t i;
        uint8_t round_idx;

        memcpy(output, plain_text, N_AES_STATE_SIZE);

        aes_step_add_round_key(output, aes_round_key);

        for (i = 0; i < N_AES_ROUND; ++i) {
                round_idx = i + 1;

                aes_step_sub_bytes(output);

                aes_step_shift_rows(output);

                if (round_idx < N_AES_ROUND) {
                        aes_step_mix_columns(output);
                }

                aes_step_add_round_key(
                    output, (aes_round_key + (round_idx * N_AES_KEY_SIZE)));
        }
}

void aes_decryption(uint8_t *cipher_text, uint8_t *output)
{
        uint8_t i;
        uint8_t round_idx;

        memcpy(output, cipher_text, N_AES_STATE_SIZE);

        aes_step_add_round_key(
            output, (aes_round_key + (N_AES_ROUND * N_AES_KEY_SIZE)));

        for (i = N_AES_ROUND; i > 0; --i) {
                round_idx = i - 1;

                aes_step_inv_shift_rows(output);
                aes_step_inv_sub_bytes(output);
                aes_step_add_round_key(
                    output, (aes_round_key + (round_idx * N_AES_KEY_SIZE)));

                if (round_idx > 0) {
                        aes_step_inv_mix_columns(output);
                }
        }
}
