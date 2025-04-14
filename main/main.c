
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_BUFFER_LEN 2048

#if defined(ALGO_AES_256)
#define AES_ALGO "AES-256"
#elif defined(ALGO_AES_192)
#define AES_ALGO "AES-192"
#else
#define AES_ALGO "AES-128"
#endif

#if defined(TYPE_AES_CBC)
#define AES_TYPE "CBC"
#elif defined(TYPE_AES_CTR)
#define AES_TYPE "CTR"
#elif defined(TYPE_AES_GCM)
#define AES_TYPE "GCM"
#else
#define AES_TYPE "ECB"
#endif

struct aes_info {
        uint8_t *key;
        uint8_t *plain;
        uint8_t *cipher;
        uint8_t *nonce;
        uint8_t *aad;
        uint8_t *tag;
        uint64_t plain_len;
        uint64_t cipher_len;
        uint64_t nonce_len;
        uint64_t aad_len;
        uint64_t tag_len;
};

const struct aes_info aes_empty = {.key = NULL,
                                   .plain = NULL,
                                   .cipher = NULL,
                                   .nonce = NULL,
                                   .aad = NULL,
                                   .tag = NULL,
                                   .plain_len = 0,
                                   .cipher_len = 0,
                                   .nonce_len = 0,
                                   .aad_len = 0,
                                   .tag_len = 0};

static void aes_info_release(struct aes_info *info)
{
        if (info->key) {
                free(info->key);
        }

        if (info->plain) {
                free(info->plain);
        }

        if (info->cipher) {
                free(info->cipher);
        }

        if (info->nonce) {
                free(info->nonce);
        }

        if (info->aad) {
                free(info->aad);
        }

        if (info->tag) {
                free(info->tag);
        }
}

static void print_hex_array(const char *label, uint8_t *data, uint8_t n_len)
{
        uint8_t i;

        printf("%s:", label);
        for (i = 0; i < n_len; ++i) {
                if (i % 8 == 0) {
                        printf("\n\t");
                }
                printf("0x%02x ", data[i]);
        }
        printf("\n");
}

int main(void)
{
        char tmp_buffer[MAX_BUFFER_LEN];
        struct aes_info tmp_info = aes_empty;
        struct aes_ctx tmp_ctx;
        enum aes_error tmp_result;

        uint64_t input_len;
        uint64_t input_align;

        printf("====== %s %s ======\n\n", AES_ALGO, AES_TYPE);

        printf("Enter the cipher key: ");
        if (fgets(tmp_buffer, sizeof(tmp_buffer), stdin) == NULL) {
                fprintf(stderr, "Error: Fail to get key!\n");
                aes_info_release(&tmp_info);
                return EXIT_FAILURE;
        }
        tmp_buffer[strcspn(tmp_buffer, " \r\n")] = '\0';

        input_len = strlen(tmp_buffer) / 2;
        if (input_len != N_AES_KEY_SIZE) {
                fprintf(stderr, "Error: Wrong key size!\n");
                aes_info_release(&tmp_info);
                return EXIT_FAILURE;
        }
        tmp_info.key = (uint8_t *)malloc(input_len);
        memset(tmp_info.key, 0x00, input_len);
        hex_str_to_bytes(tmp_buffer, tmp_info.key, input_len);

#if !defined(TYPE_AES_ECB)
        printf("Enter the Nonce: ");
        if (fgets(tmp_buffer, sizeof(tmp_buffer), stdin) == NULL) {
                fprintf(stderr, "Error: Fail to get Nonce!\n");
                aes_info_release(&tmp_info);
                return EXIT_FAILURE;
        }
        tmp_buffer[strcspn(tmp_buffer, " \r\n")] = '\0';
        input_len = strlen(tmp_buffer) / 2;
        if (strlen(tmp_buffer) % 2) {
                fprintf(stderr, "Error: Wrong size of Nonce!\n");
                aes_info_release(&tmp_info);
                return EXIT_FAILURE;
        }
        input_align = (input_len + 15) / 16 * 16;

        tmp_info.nonce = (uint8_t *)malloc(input_align);
        tmp_info.nonce_len = input_len;
        memset(tmp_info.nonce, 0x00, input_align);
        hex_str_to_bytes(tmp_buffer, tmp_info.nonce, input_len);
#endif

#if defined(TYPE_AES_GCM)
        printf("Enter the AAD: ");
        if (fgets(tmp_buffer, sizeof(tmp_buffer), stdin) == NULL) {
                fprintf(stderr, "Error: Fail to get AAD!\n");
                aes_info_release(&tmp_info);
                return EXIT_FAILURE;
        }
        tmp_buffer[strcspn(tmp_buffer, " \r\n")] = '\0';
        input_len = strlen(tmp_buffer) / 2;
        if (strlen(tmp_buffer) % 2) {
                fprintf(stderr, "Error: Wrong size of AAD!\n");
                aes_info_release(&tmp_info);
                return EXIT_FAILURE;
        }
        input_align = (input_len + 15) / 16 * 16;

        tmp_info.aad = (uint8_t *)malloc(input_align);
        tmp_info.aad_len = input_len;
        memset(tmp_info.aad, 0x00, input_align);
        hex_str_to_bytes(tmp_buffer, tmp_info.aad, input_len);
#endif

        printf("Enter the plaintext: ");
        if (fgets(tmp_buffer, sizeof(tmp_buffer), stdin) == NULL) {
                fprintf(stderr, "Error: Fail to get plaintext!\n");
                aes_info_release(&tmp_info);
                return EXIT_FAILURE;
        }
        tmp_buffer[strcspn(tmp_buffer, " \r\n")] = '\0';
        input_len = strlen(tmp_buffer) / 2;
        if (strlen(tmp_buffer) % 2) {
                fprintf(stderr, "Error: Wrong plaintext!\n");
                aes_info_release(&tmp_info);
                return EXIT_FAILURE;
        }
        input_align = (input_len + 15) / 16 * 16;

        tmp_info.plain = (uint8_t *)malloc(input_align);
        tmp_info.plain_len = input_len;
        memset(tmp_info.plain, 0x00, input_align);
        hex_str_to_bytes(tmp_buffer, tmp_info.plain, input_len);

        aes_init_key(&tmp_ctx, tmp_info.key);
#if defined(TYPE_AES_CBC)
        aes_init_iv(&tmp_ctx, tmp_info.nonce);
#endif
#if defined(TYPE_AES_CTR)
        aes_init_nonce(&tmp_ctx, tmp_info.nonce);
#endif
#if defined(TYPE_AES_GCM)
        aes_init_aad(&tmp_ctx, tmp_info.aad, tmp_info.aad_len);
        aes_init_ghash_h(&tmp_ctx);
        aes_init_j0(&tmp_ctx, tmp_info.nonce, tmp_info.nonce_len);
#endif

        tmp_ctx.input = tmp_info.plain;
        tmp_ctx.input_len = tmp_info.plain_len;
        print_hex_array("\nPlaintext", tmp_ctx.input, tmp_ctx.input_len);

        tmp_ctx.output = NULL;
        tmp_ctx.output_len = 0;

#if defined(TYPE_AES_ECB)
        tmp_result = aes_ecb_encryption(&tmp_ctx);
#endif
#if defined(TYPE_AES_CBC)
        tmp_result = aes_cbc_encryption(&tmp_ctx);
#endif
#if defined(TYPE_AES_CTR)
        tmp_result = aes_ctr_encryption(&tmp_ctx);
#endif
#if defined(TYPE_AES_GCM)
        tmp_result = aes_gcm_encryption(&tmp_ctx);
#endif

        printf("\n***Encryption result: \n");
        if (tmp_result != AES_SUCCESS) {
                fprintf(stderr, "Error: AES encryption failed! error: %d\n",
                        tmp_result);
                aes_info_release(&tmp_info);
                return EXIT_FAILURE;
        }

        print_hex_array("\nCipher", tmp_ctx.output, tmp_ctx.output_len);
#if defined(TYPE_AES_GCM)
        print_hex_array("\nTag", tmp_ctx.tag, tmp_ctx.tag_len);
#endif

        // take the cipher as new input
        free(tmp_info.plain);
        tmp_info.plain = NULL;

        tmp_ctx.input = tmp_ctx.output;
        tmp_ctx.input_len = tmp_ctx.output_len;
        tmp_ctx.output = NULL;
        tmp_ctx.output_len = 0;

#if defined(TYPE_AES_ECB)
        tmp_result = aes_ecb_decryption(&tmp_ctx);
#endif
#if defined(TYPE_AES_CBC)
        tmp_result = aes_cbc_decryption(&tmp_ctx);
#endif
#if defined(TYPE_AES_CTR)
        tmp_result = aes_ctr_encryption(&tmp_ctx);
#endif
#if defined(TYPE_AES_GCM)
        // notice that tmp_ctx->tag was generated by encryption, always matched.
        tmp_result = aes_gcm_decryption(&tmp_ctx);
#endif

        printf("\n***Decryption result: \n");
        if (tmp_result != AES_SUCCESS) {
                fprintf(stderr, "Error: AES decryption failed! error: %d\n",
                        tmp_result);
                free(tmp_ctx.input);
                aes_info_release(&tmp_info);
                return EXIT_FAILURE;
        }

        print_hex_array("\nPlaintext", tmp_ctx.output, tmp_ctx.output_len);

        free(tmp_ctx.input);
        aes_context_release(&tmp_ctx);
        aes_info_release(&tmp_info);

        return EXIT_SUCCESS;
}