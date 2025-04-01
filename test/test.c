
#include "aes.h"

#define N_ECB_TEST 4
#define MAX_SIZE_ECB_TEST 16

#define N_CBC_TEST 4
#define MAX_SIZE_CBC_TEST 16

#define N_CTR_TEST 4
#define MAX_SIZE_CTR_TEST 16

#define N_GCM_TEST 4
#define MAX_SIZE_GCM_TEST 16

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

static void compare_result(const char *item, uint8_t *data, uint8_t *src,
                           uint8_t n_len)
{
        printf("-- %s ", item);
        if (memcmp(data, src, n_len) == 0)
                printf("PASS!\n");
        else
                printf("FAIL!\n");
}

#if defined(TYPE_AES_ECB)
static void aes_test_ecb(void)
{
        /* AES128 ECB test vectors */
        char *vector_text[N_ECB_TEST] = {"6bc1bee22e409f96e93d7e117393172a",
                                         "ae2d8a571e03ac9c9eb76fac45af8e51",
                                         "30c81c46a35ce411e5fbc1191a0a52ef",
                                         "f69f2445df4f9b17ad2b417be66c3710"};
        char *vector_cipher[N_ECB_TEST] = {"3ad77bb40d7a3660a89ecaf32466ef97",
                                           "f5d3d58503b9699de785895a96fdbaaf",
                                           "43b1cd7f598ece23881b00e3ed030688",
                                           "7b0c785e27e8ad3f8223207104725dd4"};
        char *vector_key = "2b7e151628aed2a6abf7158809cf4f3c";

        uint8_t tmp_plain[MAX_SIZE_ECB_TEST];
        uint8_t tmp_cipher[MAX_SIZE_ECB_TEST];
        uint8_t tmp_key[N_AES_KEY_SIZE];
        char *ptr_test, *ptr_cipher;

        printf("=== AES-128 ECB test ===\n");

        struct aes_ctx aes_context;
        enum aes_error aes_result;

        for (uint8_t test_idx = 0; test_idx < N_ECB_TEST; ++test_idx) {
                printf("\n[TEST %d]\n", test_idx + 1);

                // key may be different
                hex_str_to_bytes(vector_key, tmp_key, N_AES_KEY_SIZE);
                aes_key_init(&aes_context, tmp_key);

                ptr_test = vector_text[test_idx];
                ptr_cipher = vector_cipher[test_idx];

                uint32_t plain_size = strlen(ptr_test) / 2;
                hex_str_to_bytes(ptr_test, tmp_plain, plain_size);
                uint32_t cipher_size = strlen(ptr_cipher) / 2;
                hex_str_to_bytes(ptr_cipher, tmp_cipher, cipher_size);

                print_hex_array("Plain text", tmp_plain, plain_size);

                aes_context.input = tmp_plain;
                aes_context.input_len = plain_size;
                aes_context.output = NULL;
                aes_context.output_len = 0;
                aes_result = aes_ecb_encryption(&aes_context);
                if (aes_result != AES_SUCCESS) {
                        printf("Encrypt error!! : %d\n", aes_result);
                        (void)aes_context_release(&aes_context);
                        return;
                }

                printf("Encrypted size: %d\n", aes_context.output_len);
                print_hex_array("Encryption", aes_context.output,
                                aes_context.output_len);
                compare_result("Encryption", aes_context.output, tmp_cipher,
                               cipher_size);

                // take cipher(the padded memory) as new input
                aes_context.input = aes_context.output;
                aes_context.input_len = aes_context.output_len;
                aes_context.output = NULL;
                aes_context.output_len = 0;
                aes_result = aes_ecb_decryption(&aes_context);
                if (aes_result != AES_SUCCESS) {
                        printf("Decrypt error!! : %d\n", aes_result);
                        (void)aes_context_release(&aes_context);
                        return;
                }

                printf("Decrypted size: %d\n", aes_context.output_len);
                print_hex_array("Decryption", aes_context.output,
                                aes_context.output_len);
                compare_result("Decryption", aes_context.output, tmp_plain,
                               plain_size);

                (void)aes_context_release(&aes_context);
        }
}
#endif // TYPE_AES_ECB

#if defined(TYPE_AES_CBC)
static void aes_test_cbc(void)
{
        /* AES128 CBC test vectors */
        char *vector_iv[N_CBC_TEST] = {"000102030405060708090A0B0C0D0E0F",
                                       "7649ABAC8119B246CEE98E9B12E9197D",
                                       "5086cb9b507219ee95db113a917678b2",
                                       "73bed6b8e3c1743b7116e69e22229516"};
        char *vector_text[N_CBC_TEST] = {"6bc1bee22e409f96e93d7e117393172a",
                                         "ae2d8a571e03ac9c9eb76fac45af8e51",
                                         "30c81c46a35ce411e5fbc1191a0a52ef",
                                         "f69f2445df4f9b17ad2b417be66c3710"};
        char *vector_cipher[N_CBC_TEST] = {"7649abac8119b246cee98e9b12e9197d",
                                           "5086cb9b507219ee95db113a917678b2",
                                           "73bed6b8e3c1743b7116e69e22229516",
                                           "3ff1caa1681fac09120eca307586e1a7"};
        char *vector_key = "2b7e151628aed2a6abf7158809cf4f3c";

        uint8_t tmp_plain[MAX_SIZE_CBC_TEST];
        uint8_t tmp_cipher[MAX_SIZE_CBC_TEST];
        uint8_t tmp_key[N_AES_KEY_SIZE];
        uint8_t tmp_iv[N_AES_KEY_SIZE];
        char *ptr_test, *ptr_cipher, *ptr_iv;

        printf("=== AES-128 CBC test ===\n");

        struct aes_ctx aes_context;
        enum aes_error aes_result;

        for (uint8_t test_idx = 0; test_idx < N_CBC_TEST; ++test_idx) {
                printf("\n[TEST %d]\n", test_idx + 1);

                // key may be different
                hex_str_to_bytes(vector_key, tmp_key, N_AES_KEY_SIZE);
                aes_key_init(&aes_context, tmp_key);

                ptr_test = vector_text[test_idx];
                ptr_cipher = vector_cipher[test_idx];
                ptr_iv = vector_iv[test_idx];

                hex_str_to_bytes(ptr_iv, tmp_iv, N_AES_KEY_SIZE);
                aes_iv_init(&aes_context, tmp_iv);
                print_hex_array("Init vector", tmp_iv, N_AES_KEY_SIZE);

                uint32_t plain_size = strlen(ptr_test) / 2;
                hex_str_to_bytes(ptr_test, tmp_plain, plain_size);
                uint32_t cipher_size = strlen(ptr_cipher) / 2;
                hex_str_to_bytes(ptr_cipher, tmp_cipher, cipher_size);

                print_hex_array("Plain text", tmp_plain, plain_size);

                aes_context.input = tmp_plain;
                aes_context.input_len = plain_size;
                aes_context.output = NULL;
                aes_context.output_len = 0;
                aes_result = aes_cbc_encryption(&aes_context);
                if (aes_result != AES_SUCCESS) {
                        printf("Encrypt error!! : %d\n", aes_result);
                        (void)aes_context_release(&aes_context);
                        return;
                }

                printf("Encrypted size: %d\n", aes_context.output_len);
                print_hex_array("Encryption", aes_context.output,
                                aes_context.output_len);
                compare_result("Encryption", aes_context.output, tmp_cipher,
                               cipher_size);

                // take cipher(the padded memory) as new input
                aes_context.input = aes_context.output;
                aes_context.input_len = aes_context.output_len;
                aes_context.output = NULL;
                aes_context.output_len = 0;
                aes_result = aes_cbc_decryption(&aes_context);
                if (aes_result != AES_SUCCESS) {
                        printf("Decrypt error!! : %d\n", aes_result);
                        (void)aes_context_release(&aes_context);
                        return;
                }

                printf("Decrypted size: %d\n", aes_context.output_len);
                print_hex_array("Decryption", aes_context.output,
                                aes_context.output_len);
                compare_result("Decryption", aes_context.output, tmp_plain,
                               plain_size);

                (void)aes_context_release(&aes_context);
        }
}
#endif // TYPE_AES_CBC

#if defined(TYPE_AES_CTR)
static void aes_test_ctr(void)
{
        /* AES128 CTR test vectors */
        char *vector_nonce[N_CTR_TEST] = {"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                                          "f0f1f2f3f4f5f6f7f8f9fafbfcfdff00",
                                          "f0f1f2f3f4f5f6f7f8f9fafbfcfdff01",
                                          "f0f1f2f3f4f5f6f7f8f9fafbfcfdff02"};
        char *vector_text[N_CTR_TEST] = {"6bc1bee22e409f96e93d7e117393172a",
                                         "ae2d8a571e03ac9c9eb76fac45af8e51",
                                         "30c81c46a35ce411e5fbc1191a0a52ef",
                                         "f69f2445df4f9b17ad2b417be66c3710"};
        char *vector_cipher[N_CTR_TEST] = {"874d6191b620e3261bef6864990db6ce",
                                           "9806f66b7970fdff8617187bb9fffdff",
                                           "5ae4df3edbd5d35e5b4f09020db03eab",
                                           "1e031dda2fbe03d1792170a0f3009cee"};
        char *vector_key = "2b7e151628aed2a6abf7158809cf4f3c";

        uint8_t tmp_plain[MAX_SIZE_CTR_TEST];
        uint8_t tmp_cipher[MAX_SIZE_CTR_TEST];
        uint8_t tmp_key[N_AES_KEY_SIZE];
        uint8_t tmp_nonce[N_AES_NONCE_SIZE];
        char *ptr_test, *ptr_cipher, *ptr_nonce;

        printf("=== AES-128 CTR test ===\n");

        struct aes_ctx aes_context;
        enum aes_error aes_result;

        for (uint8_t test_idx = 0; test_idx < N_CBC_TEST; ++test_idx) {
                printf("\n[TEST %d]\n", test_idx + 1);

                // key may be different
                hex_str_to_bytes(vector_key, tmp_key, N_AES_KEY_SIZE);
                aes_key_init(&aes_context, tmp_key);

                ptr_test = vector_text[test_idx];
                ptr_cipher = vector_cipher[test_idx];
                ptr_nonce = vector_nonce[test_idx];

                hex_str_to_bytes(ptr_nonce, tmp_nonce, N_AES_NONCE_SIZE);
                aes_nonce_init(&aes_context, tmp_nonce);
                print_hex_array("Init Nonce", tmp_nonce, N_AES_NONCE_SIZE);

                uint32_t plain_size = strlen(ptr_test) / 2;
                hex_str_to_bytes(ptr_test, tmp_plain, plain_size);
                uint32_t cipher_size = strlen(ptr_cipher) / 2;
                hex_str_to_bytes(ptr_cipher, tmp_cipher, cipher_size);

                print_hex_array("Plain text", tmp_plain, plain_size);

                aes_context.input = tmp_plain;
                aes_context.input_len = plain_size;
                aes_context.output = NULL;
                aes_context.output_len = 0;
                aes_result = aes_ctr_encryption(&aes_context);
                if (aes_result != AES_SUCCESS) {
                        printf("Encrypt error!! : %d\n", aes_result);
                        (void)aes_context_release(&aes_context);
                        return;
                }

                printf("Encrypted size: %d\n", aes_context.output_len);
                print_hex_array("Encryption", aes_context.output,
                                aes_context.output_len);
                compare_result("Encryption", aes_context.output, tmp_cipher,
                               cipher_size);

                // take cipher(the padded memory) as new input
                aes_context.input = aes_context.output;
                aes_context.input_len = aes_context.output_len;
                aes_context.output = NULL;
                aes_context.output_len = 0;
                // AES-CTR use same encpyt/decrypt process 
                aes_result = aes_ctr_encryption(&aes_context);
                if (aes_result != AES_SUCCESS) {
                        printf("Decrypt error!! : %d\n", aes_result);
                        (void)aes_context_release(&aes_context);
                        return;
                }

                printf("Decrypted size: %d\n", aes_context.output_len);
                print_hex_array("Decryption", aes_context.output,
                                aes_context.output_len);
                compare_result("Decryption", aes_context.output, tmp_plain,
                               plain_size);

                (void)aes_context_release(&aes_context);
        }
}
#endif // TYPE_AES_CTR

int main(void)
{
#if defined(TYPE_AES_ECB)
        aes_test_ecb();
#endif
#if defined(TYPE_AES_CBC)
        aes_test_cbc();
#endif
#if defined(TYPE_AES_CTR)
        aes_test_ctr();
#endif
        return 0;
}