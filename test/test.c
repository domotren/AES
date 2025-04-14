
#include "aes.h"
#include <stdio.h>

#define MAX_BUFFER_LEN 256
#define MAX_STR_LEN 2048

#define DBG_LOG_ENABLED 0

struct test_case {
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

const struct test_case test_empty = {.key = NULL,
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

static char tmp_line[MAX_STR_LEN];

#if DBG_LOG_ENABLED == 1
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
#endif

static void text_case_release(struct test_case *test)
{
        free(test->key);
        free(test->plain);
        free(test->cipher);
        test->key = NULL;
        test->plain = NULL;
        test->plain_len = 0;
        test->cipher = NULL;
        test->cipher_len = 0;
#if !defined(MODE_AES_ECB)
        free(test->nonce);
        test->nonce = NULL;
        test->nonce_len = 0;
#endif
#if defined(MODE_AES_GCM)
        free(test->aad);
        test->aad = NULL;
        test->aad_len = 0;
        free(test->tag);
        test->tag = NULL;
        test->tag_len = 0;
#endif
}

#if defined(MODE_AES_ECB)
static void aes_test_ecb(void)
{
#if defined(TYPE_AES_128)
        printf("=== AES-128 ECB test ===\n");
        char *vector_file = "test/test_vectors/aes_128_ecb";
#endif
#if defined(TYPE_AES_192)
        printf("=== AES-192 ECB test ===\n");
        char *vector_file = "test/test_vectors/aes_192_ecb";
#endif
#if defined(TYPE_AES_256)
        printf("=== AES-256 ECB test ===\n");
        char *vector_file = "test/test_vectors/aes_256_ecb";
#endif

        struct test_case aes_test = test_empty;
        struct aes_ctx aes_context;
        enum aes_error aes_result;

        FILE *file = fopen(vector_file, "r");
        if (!file) {
                printf("Fail to open %s !!\n", vector_file);
                return;
        }

        int test_trigger = 0;
        int test_idx = 0;
        int pass_case = 0;

        while (fgets(tmp_line, sizeof(tmp_line), file)) {

                if (tmp_line[0] == '#' || tmp_line[0] == '\0') {
                        continue;
                }

                char *token = strtok(tmp_line, " ");
                if (token != NULL) {
                        char *tmp_div = strchr(token, '=');
                        if (!tmp_div) {
                                continue;
                        }
                        *tmp_div = '\0';
                        char *k = token;
                        char *v = tmp_div + 1;
                        v[strcspn(v, " \r\n")] = '\0';

                        if (strcmp(k, "key") == 0) {
                                uint64_t k_len = strlen(v) / 2;
                                uint64_t k_align = (k_len + 15) / 16 * 16;
                                aes_test.key = (uint8_t *)malloc(k_align);
                                memset(aes_test.key, 0x00, k_align);
                                hex_str_to_bytes(v, aes_test.key, k_len);
                        } else if (strcmp(k, "plain") == 0) {
                                uint64_t p_len = strlen(v) / 2;
                                uint64_t p_align = (p_len + 15) / 16 * 16;
                                aes_test.plain = (uint8_t *)malloc(p_align);
                                memset(aes_test.plain, 0x00, p_align);
                                aes_test.plain_len = p_len;
                                hex_str_to_bytes(v, aes_test.plain, p_len);
                        } else if (strcmp(k, "cipher") == 0) {
                                uint64_t c_len = strlen(v) / 2;
                                uint64_t c_align = (c_len + 15) / 16 * 16;
                                aes_test.cipher = (uint8_t *)malloc(c_align);
                                memset(aes_test.cipher, 0x00, c_align);
                                aes_test.cipher_len = c_len;
                                hex_str_to_bytes(v, aes_test.cipher, c_len);
                                test_trigger = 1;
                                ++test_idx;
                        }
                }

                if (test_trigger == 1) {
                        printf("\n[TEST %d] ", test_idx);
                        aes_init_key(&aes_context, aes_test.key);
                        aes_context.input = aes_test.plain;
                        aes_context.input_len = aes_test.plain_len;
                        aes_context.output = NULL;
                        aes_context.output_len = 0;
                        aes_result = aes_ecb_encryption(&aes_context);

                        if (aes_result != AES_SUCCESS) {
                                printf("ERROR (Encryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Encryption error : %d\n", aes_result);
#endif
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        if (memcmp(aes_context.output, aes_test.cipher,
                                   aes_test.cipher_len) != 0) {
                                printf("FAIL (Encryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Encrypted size: %ld\n",
                                       aes_context.output_len);
                                print_hex_array("Encryption",
                                                aes_context.output,
                                                aes_context.output_len);
#endif
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        // take cipher(the padded memory) as new input
                        aes_context.input = aes_context.output;
                        aes_context.input_len = aes_context.output_len;
                        aes_context.output = NULL;
                        aes_context.output_len = 0;
                        aes_result = aes_ecb_decryption(&aes_context);

                        if (aes_result != AES_SUCCESS) {
                                printf("ERROR (Decryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Decryption error : %d\n", aes_result);
#endif
                                free(aes_context.input);
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        if (memcmp(aes_context.output, aes_test.plain,
                                   aes_test.plain_len) != 0) {
                                printf("FAIL (Decryption)\n");

#if DBG_LOG_ENABLED == 1
                                printf("Decrypted size: %ld\n",
                                       aes_context.output_len);
                                print_hex_array("Decryption",
                                                aes_context.output,
                                                aes_context.output_len);
#endif
                                free(aes_context.input);
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        free(aes_context.input);
                        (void)aes_context_release(&aes_context);
                        text_case_release(&aes_test);
                        test_trigger = 0;
                        printf("PASS\n");
                        ++pass_case;
                }
        }
        fclose(file);

        printf("\n***** PASS : %d / %d *****\n", pass_case, test_idx);
}
#endif // MODE_AES_ECB

#if defined(MODE_AES_CBC)
static void aes_test_cbc(void)
{
#if defined(TYPE_AES_128)
        printf("=== AES-128 CBC test ===\n");
        char *vector_file = "test/test_vectors/aes_128_cbc";
#endif
#if defined(TYPE_AES_192)
        printf("=== AES-192 CBC test ===\n");
        char *vector_file = "test/test_vectors/aes_192_cbc";
#endif
#if defined(TYPE_AES_256)
        printf("=== AES-256 CBC test ===\n");
        char *vector_file = "test/test_vectors/aes_256_cbc";
#endif

        struct test_case aes_test = test_empty;
        struct aes_ctx aes_context;
        enum aes_error aes_result;

        FILE *file = fopen(vector_file, "r");
        if (!file) {
                printf("Fail to open %s !!\n", vector_file);
                return;
        }

        int test_trigger = 0;
        int test_idx = 0;
        int pass_case = 0;

        while (fgets(tmp_line, sizeof(tmp_line), file)) {

                if (tmp_line[0] == '#' || tmp_line[0] == '\0') {
                        continue;
                }

                char *token = strtok(tmp_line, " ");
                if (token != NULL) {
                        char *tmp_div = strchr(token, '=');
                        if (!tmp_div) {
                                continue;
                        }
                        *tmp_div = '\0';
                        char *k = token;
                        char *v = tmp_div + 1;
                        v[strcspn(v, " \r\n")] = '\0';

                        if (strcmp(k, "key") == 0) {
                                uint64_t k_len = strlen(v) / 2;
                                uint64_t k_align = (k_len + 15) / 16 * 16;
                                aes_test.key = (uint8_t *)malloc(k_align);
                                memset(aes_test.key, 0x00, k_align);
                                hex_str_to_bytes(v, aes_test.key, k_len);
                        } else if (strcmp(k, "iv") == 0) {
                                uint64_t i_len = strlen(v) / 2;
                                uint64_t i_align = (i_len + 15) / 16 * 16;
                                aes_test.nonce = (uint8_t *)malloc(i_align);
                                memset(aes_test.nonce, 0x00, i_align);
                                aes_test.nonce_len = i_len;
                                hex_str_to_bytes(v, aes_test.nonce, i_len);
                        } else if (strcmp(k, "plain") == 0) {
                                uint64_t p_len = strlen(v) / 2;
                                uint64_t p_align = (p_len + 15) / 16 * 16;
                                aes_test.plain = (uint8_t *)malloc(p_align);
                                memset(aes_test.plain, 0x00, p_align);
                                aes_test.plain_len = p_len;
                                hex_str_to_bytes(v, aes_test.plain, p_len);
                        } else if (strcmp(k, "cipher") == 0) {
                                uint64_t c_len = strlen(v) / 2;
                                uint64_t c_align = (c_len + 15) / 16 * 16;
                                aes_test.cipher = (uint8_t *)malloc(c_align);
                                memset(aes_test.cipher, 0x00, c_align);
                                aes_test.cipher_len = c_len;
                                hex_str_to_bytes(v, aes_test.cipher, c_len);
                                test_trigger = 1;
                                ++test_idx;
                        }
                }

                if (test_trigger == 1) {
                        printf("\n[TEST %d] ", test_idx);
                        aes_init_key(&aes_context, aes_test.key);
                        aes_init_iv(&aes_context, aes_test.nonce);
                        aes_context.input = aes_test.plain;
                        aes_context.input_len = aes_test.plain_len;
                        aes_context.output = NULL;
                        aes_context.output_len = 0;
                        aes_result = aes_cbc_encryption(&aes_context);

                        if (aes_result != AES_SUCCESS) {
                                printf("ERROR (Encryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Encryption error : %d\n", aes_result);
#endif
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        if (memcmp(aes_context.output, aes_test.cipher,
                                   aes_test.cipher_len) != 0) {
                                printf("FAIL (Encryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Encrypted size: %ld\n",
                                       aes_context.output_len);
                                print_hex_array("Encryption",
                                                aes_context.output,
                                                aes_context.output_len);
#endif
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        // take cipher(the padded memory) as new input
                        aes_context.input = aes_context.output;
                        aes_context.input_len = aes_context.output_len;
                        aes_context.output = NULL;
                        aes_context.output_len = 0;
                        aes_result = aes_cbc_decryption(&aes_context);

                        if (aes_result != AES_SUCCESS) {
                                printf("ERROR (Decryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Decryption error : %d\n", aes_result);
#endif
                                free(aes_context.input);
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        if (memcmp(aes_context.output, aes_test.plain,
                                   aes_test.plain_len) != 0) {
                                printf("FAIL (Decryption)\n");

#if DBG_LOG_ENABLED == 1
                                printf("Decrypted size: %ld\n",
                                       aes_context.output_len);
                                print_hex_array("Decryption",
                                                aes_context.output,
                                                aes_context.output_len);
#endif
                                free(aes_context.input);
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        free(aes_context.input);
                        (void)aes_context_release(&aes_context);
                        text_case_release(&aes_test);
                        test_trigger = 0;
                        printf("PASS\n");
                        ++pass_case;
                }
        }
        fclose(file);

        printf("\n***** PASS : %d / %d *****\n", pass_case, test_idx);
}
#endif // MODE_AES_CBC

#if defined(MODE_AES_CTR)
static void aes_test_ctr(void)
{
#if defined(TYPE_AES_128)
        printf("=== AES-128 CTR test ===\n");
        char *vector_file = "test/test_vectors/aes_128_ctr";
#endif
#if defined(TYPE_AES_192)
        printf("=== AES-192 CTR test ===\n");
        char *vector_file = "test/test_vectors/aes_192_ctr";
#endif
#if defined(TYPE_AES_256)
        printf("=== AES-256 CTR test ===\n");
        char *vector_file = "test/test_vectors/aes_256_ctr";
#endif

        struct test_case aes_test = test_empty;
        struct aes_ctx aes_context;
        enum aes_error aes_result;

        FILE *file = fopen(vector_file, "r");
        if (!file) {
                printf("Fail to open %s !!\n", vector_file);
                return;
        }

        int test_trigger = 0;
        int test_idx = 0;
        int pass_case = 0;

        while (fgets(tmp_line, sizeof(tmp_line), file)) {

                if (tmp_line[0] == '#' || tmp_line[0] == '\0') {
                        continue;
                }

                char *token = strtok(tmp_line, " ");
                if (token != NULL) {
                        char *tmp_div = strchr(token, '=');
                        if (!tmp_div) {
                                continue;
                        }
                        *tmp_div = '\0';
                        char *k = token;
                        char *v = tmp_div + 1;
                        v[strcspn(v, " \r\n")] = '\0';

                        if (strcmp(k, "key") == 0) {
                                uint64_t k_len = strlen(v) / 2;
                                uint64_t k_align = (k_len + 15) / 16 * 16;
                                aes_test.key = (uint8_t *)malloc(k_align);
                                memset(aes_test.key, 0x00, k_align);
                                hex_str_to_bytes(v, aes_test.key, k_len);
                        } else if (strcmp(k, "iv") == 0) {
                                uint64_t i_len = strlen(v) / 2;
                                uint64_t i_align = (i_len + 15) / 16 * 16;
                                aes_test.nonce = (uint8_t *)malloc(i_align);
                                memset(aes_test.nonce, 0x00, i_align);
                                aes_test.nonce_len = i_len;
                                hex_str_to_bytes(v, aes_test.nonce, i_len);
                        } else if (strcmp(k, "plain") == 0) {
                                uint64_t p_len = strlen(v) / 2;
                                uint64_t p_align = (p_len + 15) / 16 * 16;
                                aes_test.plain = (uint8_t *)malloc(p_align);
                                memset(aes_test.plain, 0x00, p_align);
                                aes_test.plain_len = p_len;
                                hex_str_to_bytes(v, aes_test.plain, p_len);
                        } else if (strcmp(k, "cipher") == 0) {
                                uint64_t c_len = strlen(v) / 2;
                                uint64_t c_align = (c_len + 15) / 16 * 16;
                                aes_test.cipher = (uint8_t *)malloc(c_align);
                                memset(aes_test.cipher, 0x00, c_align);
                                aes_test.cipher_len = c_len;
                                hex_str_to_bytes(v, aes_test.cipher, c_len);
                                test_trigger = 1;
                                ++test_idx;
                        }
                }

                if (test_trigger == 1) {
                        printf("\n[TEST %d] ", test_idx);
                        aes_init_key(&aes_context, aes_test.key);
                        aes_init_nonce(&aes_context, aes_test.nonce);
                        aes_context.input = aes_test.plain;
                        aes_context.input_len = aes_test.plain_len;
                        aes_context.output = NULL;
                        aes_context.output_len = 0;
                        aes_result = aes_ctr_encryption(&aes_context);

                        if (aes_result != AES_SUCCESS) {
                                printf("ERROR (Encryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Encryption error : %d\n", aes_result);
#endif
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        if (memcmp(aes_context.output, aes_test.cipher,
                                   aes_test.cipher_len) != 0) {
                                printf("FAIL (Encryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Encrypted size: %ld\n",
                                       aes_context.output_len);
                                print_hex_array("Encryption",
                                                aes_context.output,
                                                aes_context.output_len);
#endif
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        free(aes_context.output);

                        aes_context.input = aes_test.cipher;
                        aes_context.input_len = aes_test.cipher_len;
                        aes_context.output = NULL;
                        aes_context.output_len = 0;
                        aes_result = aes_ctr_encryption(&aes_context);

                        if (aes_result != AES_SUCCESS) {
                                printf("ERROR (Decryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Decryption error : %d\n", aes_result);
#endif
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        if (memcmp(aes_context.output, aes_test.plain,
                                   aes_test.plain_len) != 0) {
                                printf("FAIL (Decryption)\n");

#if DBG_LOG_ENABLED == 1
                                printf("Decrypted size: %ld\n",
                                       aes_context.output_len);
                                print_hex_array("Decryption",
                                                aes_context.output,
                                                aes_context.output_len);
#endif
                                (void)aes_context_release(&aes_context);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        (void)aes_context_release(&aes_context);
                        text_case_release(&aes_test);
                        test_trigger = 0;
                        printf("PASS\n");
                        ++pass_case;
                }
        }
        fclose(file);

        printf("\n***** PASS : %d / %d *****\n", pass_case, test_idx);
}
#endif // MODE_AES_CTR

#if defined(MODE_AES_GCM)
static void aes_test_gcm(void)
{
#if defined(TYPE_AES_128)
        printf("=== AES-128 GCM test ===\n");
        char *vector_file = "test/test_vectors/aes_128_gcm";
#endif
#if defined(TYPE_AES_192)
        printf("=== AES-192 GCM test ===\n");
        char *vector_file = "test/test_vectors/aes_192_gcm";
#endif
#if defined(TYPE_AES_256)
        printf("=== AES-256 GCM test ===\n");
        char *vector_file = "test/test_vectors/aes_256_gcm";
#endif

        struct test_case aes_test = test_empty;
        struct aes_ctx aes_context_enc;
        struct aes_ctx aes_context_dec;

        enum aes_error aes_result;

        FILE *file = fopen(vector_file, "r");
        if (!file) {
                printf("Fail to open %s !!\n", vector_file);
                return;
        }

        int test_trigger = 0;
        int test_idx = 0;
        int pass_case = 0;

        while (fgets(tmp_line, sizeof(tmp_line), file)) {

                if (tmp_line[0] == '#' || tmp_line[0] == '\0') {
                        continue;
                }

                char *token = strtok(tmp_line, " ");
                if (token != NULL) {
                        char *tmp_div = strchr(token, '=');
                        if (!tmp_div) {
                                continue;
                        }
                        *tmp_div = '\0';
                        char *k = token;
                        char *v = tmp_div + 1;
                        v[strcspn(v, " \r\n")] = '\0';

                        if (strcmp(k, "key") == 0) {
                                uint64_t k_len = strlen(v) / 2;
                                uint64_t k_align = (k_len + 15) / 16 * 16;
                                aes_test.key = (uint8_t *)malloc(k_align);
                                memset(aes_test.key, 0x00, k_align);
                                hex_str_to_bytes(v, aes_test.key, k_len);
                        } else if (strcmp(k, "iv") == 0) {
                                uint64_t i_len = strlen(v) / 2;
                                uint64_t i_align = (i_len + 15) / 16 * 16;
                                aes_test.nonce = (uint8_t *)malloc(i_align);
                                memset(aes_test.nonce, 0x00, i_align);
                                aes_test.nonce_len = i_len;
                                hex_str_to_bytes(v, aes_test.nonce, i_len);
                        } else if (strcmp(k, "aad") == 0) {
                                uint64_t a_len = strlen(v) / 2;
                                uint64_t a_align = (a_len + 15) / 16 * 16;
                                aes_test.aad = (uint8_t *)malloc(a_align);
                                memset(aes_test.aad, 0x00, a_align);
                                aes_test.aad_len = a_len;
                                hex_str_to_bytes(v, aes_test.aad, a_len);
                        } else if (strcmp(k, "tag") == 0) {
                                uint64_t t_len = strlen(v) / 2;
                                aes_test.tag = (uint8_t *)malloc(t_len);
                                memset(aes_test.tag, 0x00, t_len);
                                aes_test.tag_len = t_len;
                                hex_str_to_bytes(v, aes_test.tag, t_len);
                        } else if (strcmp(k, "plain") == 0) {
                                uint64_t p_len = strlen(v) / 2;
                                uint64_t p_align = (p_len + 15) / 16 * 16;
                                aes_test.plain = (uint8_t *)malloc(p_align);
                                memset(aes_test.plain, 0x00, p_align);
                                aes_test.plain_len = p_len;
                                hex_str_to_bytes(v, aes_test.plain, p_len);
                        } else if (strcmp(k, "cipher") == 0) {
                                uint64_t c_len = strlen(v) / 2;
                                uint64_t c_align = (c_len + 15) / 16 * 16;
                                aes_test.cipher = (uint8_t *)malloc(c_align);
                                memset(aes_test.cipher, 0x00, c_align);
                                aes_test.cipher_len = c_len;
                                hex_str_to_bytes(v, aes_test.cipher, c_len);
                                test_trigger = 1;
                                ++test_idx;
                        }
                }

                if (test_trigger == 1) {
                        printf("\n[TEST %d] ", test_idx);
                        aes_init_key(&aes_context_enc, aes_test.key);
                        aes_init_aad(&aes_context_enc, aes_test.aad,
                                     aes_test.aad_len);
                        aes_init_ghash_h(&aes_context_enc);
                        aes_init_j0(&aes_context_enc, aes_test.nonce,
                                    aes_test.nonce_len);

                        aes_context_enc.input = aes_test.plain;
                        aes_context_enc.input_len = aes_test.plain_len;
                        aes_context_enc.output = NULL;
                        aes_context_enc.output_len = 0;
                        aes_result = aes_gcm_encryption(&aes_context_enc);

                        if (aes_result != AES_SUCCESS) {
                                printf("ERROR (Encryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Encryption error : %d\n", aes_result);
#endif
                                (void)aes_context_release(&aes_context_enc);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        if (memcmp(aes_context_enc.output, aes_test.cipher,
                                   aes_test.cipher_len) != 0) {
                                printf("FAIL (Encryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Encrypted size: %ld\n",
                                       aes_context_enc.output_len);
                                print_hex_array("Encryption",
                                                aes_context_enc.output,
                                                aes_context_enc.output_len);
                                printf("Cipher size: %ld\n",
                                       aes_test.cipher_len);
                                print_hex_array("Cipher", aes_test.cipher,
                                                aes_test.cipher_len);
#endif
                                (void)aes_context_release(&aes_context_enc);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        (void)aes_context_release(&aes_context_enc);

                        aes_init_key(&aes_context_dec, aes_test.key);
                        aes_init_aad(&aes_context_dec, aes_test.aad,
                                     aes_test.aad_len);
                        aes_init_ghash_h(&aes_context_dec);
                        aes_init_j0(&aes_context_dec, aes_test.nonce,
                                    aes_test.nonce_len);
                        // tag for AES-GCM decryption is necessary!
                        aes_init_tag(&aes_context_dec, aes_test.tag,
                                     aes_test.tag_len);

                        aes_context_dec.input = aes_test.cipher;
                        aes_context_dec.input_len = aes_test.cipher_len;
                        aes_context_dec.output = NULL;
                        aes_context_dec.output_len = 0;
                        aes_result = aes_gcm_decryption(&aes_context_dec);

                        if (aes_result != AES_SUCCESS) {
                                printf("ERROR (Decryption)\n");
#if DBG_LOG_ENABLED == 1
                                printf("Decryption error : %d\n", aes_result);
#endif
                                (void)aes_context_release(&aes_context_dec);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        if (memcmp(aes_context_dec.output, aes_test.plain,
                                   aes_test.plain_len) != 0) {
                                printf("FAIL (Decryption)\n");

#if DBG_LOG_ENABLED == 1
                                printf("Decrypted size: %ld\n",
                                       aes_context_dec.output_len);
                                print_hex_array("Decryption",
                                                aes_context_dec.output,
                                                aes_context_dec.output_len);
#endif
                                (void)aes_context_release(&aes_context_dec);
                                text_case_release(&aes_test);
                                test_trigger = 0;
                                continue;
                        }

                        (void)aes_context_release(&aes_context_dec);
                        text_case_release(&aes_test);
                        test_trigger = 0;
                        printf("PASS\n");
                        ++pass_case;
                }
        }
        fclose(file);

        printf("\n***** PASS : %d / %d *****\n", pass_case, test_idx);
}
#endif // MODE_AES_GCM

int main(void)
{
#if defined(MODE_AES_ECB)
        aes_test_ecb();
#endif
#if defined(MODE_AES_CBC)
        aes_test_cbc();
#endif
#if defined(MODE_AES_CTR)
        aes_test_ctr();
#endif
#if defined(MODE_AES_GCM)
        aes_test_gcm();
#endif
        return 0;
}