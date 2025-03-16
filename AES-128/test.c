
#include <stdio.h>
#include <stdlib.h>

#include "aes128.h"

uint8_t aes_round_key[N_AES_KEY_EXPAND_SIZE];
uint8_t aes_key[N_AES_KEY_SIZE];

int main(void)
{
        /* AES128 ECB test vectors */
        uint8_t vector_1_text[N_AES_STATE_SIZE] = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
        uint8_t vector_1_cipher[N_AES_STATE_SIZE] = {
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
        uint8_t vector_2_text[N_AES_STATE_SIZE] = {
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
        uint8_t vector_2_cipher[N_AES_STATE_SIZE] = {
            0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
            0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf};
        uint8_t vector_3_text[N_AES_STATE_SIZE] = {
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef};
        uint8_t vector_3_cipher[N_AES_STATE_SIZE] = {
            0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
            0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88};
        uint8_t vector_4_text[N_AES_STATE_SIZE] = {
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
        uint8_t vector_4_cipher[N_AES_STATE_SIZE] = {
            0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
            0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4};
        uint8_t vector_key[N_AES_KEY_SIZE] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

        uint8_t tmp_plain_text[N_AES_STATE_SIZE];
        uint8_t tmp_output[N_AES_STATE_SIZE];
        uint8_t i;

        printf("=== AES-128 ECB test ===\n");
        memcpy(aes_key, vector_key, N_AES_KEY_SIZE);
        aes_init(aes_round_key, aes_key);

        printf("\n[TEST 1]\n");
        memcpy(tmp_plain_text, vector_1_text, N_AES_STATE_SIZE);

        printf("plain text: \n\t");
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                printf("0x%02x ", tmp_plain_text[i]);
        }
        printf("\n");

        aes_encryption(tmp_plain_text, aes_round_key, tmp_output);

        printf("encryption text: \n\t");
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                printf("0x%02x ", tmp_output[i]);
        }
        printf("\n");

        if (memcmp(tmp_output, vector_1_cipher, N_AES_STATE_SIZE) == 0)
                printf("-- Encryption PASS!\n");
        else
                printf("-- Encryption FAIL!\n");

        aes_decryption(tmp_output, aes_round_key, tmp_output);

        if (memcmp(tmp_output, vector_1_text, N_AES_STATE_SIZE) == 0)
                printf("-- Decryption PASS!\n");
        else
                printf("-- Decryption FAIL!\n");

        printf("\n[TEST 2]\n");
        memcpy(tmp_plain_text, vector_2_text, N_AES_STATE_SIZE);

        printf("plain text: \n\t");
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                printf("0x%02x ", tmp_plain_text[i]);
        }
        printf("\n");

        aes_encryption(tmp_plain_text, aes_round_key, tmp_output);

        printf("encryption text: \n\t");
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                printf("0x%02x ", tmp_output[i]);
        }
        printf("\n");

        if (memcmp(tmp_output, vector_2_cipher, N_AES_STATE_SIZE) == 0)
                printf("-- Encryption PASS!\n");
        else
                printf("-- Encryption FAIL!\n");

        aes_decryption(tmp_output, aes_round_key, tmp_output);

        if (memcmp(tmp_output, vector_2_text, N_AES_STATE_SIZE) == 0)
                printf("-- Decryption PASS!\n");
        else
                printf("-- Decryption FAIL!\n");

        printf("\n[TEST 3]\n");
        memcpy(tmp_plain_text, vector_3_text, N_AES_STATE_SIZE);

        printf("plain text: \n\t");
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                printf("0x%02x ", tmp_plain_text[i]);
        }
        printf("\n");

        aes_encryption(tmp_plain_text, aes_round_key, tmp_output);

        printf("encryption text: \n\t");
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                printf("0x%02x ", tmp_output[i]);
        }
        printf("\n");

        if (memcmp(tmp_output, vector_3_cipher, N_AES_STATE_SIZE) == 0)
                printf("-- Encryption PASS!\n");
        else
                printf("-- Encryption FAIL!\n");

        aes_decryption(tmp_output, aes_round_key, tmp_output);

        if (memcmp(tmp_output, vector_3_text, N_AES_STATE_SIZE) == 0)
                printf("-- Decryption PASS!\n");
        else
                printf("-- Decryption FAIL!\n");

        printf("\n[TEST 4]\n");
        memcpy(tmp_plain_text, vector_4_text, N_AES_STATE_SIZE);

        printf("plain text: \n\t");
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                printf("0x%02x ", tmp_plain_text[i]);
        }
        printf("\n");

        aes_encryption(tmp_plain_text, aes_round_key, tmp_output);

        printf("encryption text: \n\t");
        for (i = 0; i < N_AES_STATE_SIZE; ++i) {
                printf("0x%02x ", tmp_output[i]);
        }
        printf("\n");

        if (memcmp(tmp_output, vector_4_cipher, N_AES_STATE_SIZE) == 0)
                printf("-- Encryption PASS!\n");
        else
                printf("-- Encryption FAIL!\n");

        aes_decryption(tmp_output, aes_round_key, tmp_output);

        if (memcmp(tmp_output, vector_4_text, N_AES_STATE_SIZE) == 0)
                printf("-- Decryption PASS!\n");
        else
                printf("-- Decryption FAIL!\n");

        return 0;
}
