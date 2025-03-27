
#include <stdio.h>
#include <stdlib.h>

#include "aes128.h"

#define N_ECB_TEST 4
#define MAX_SIZE_ECB_TEST 16

#define N_CBC_TEST 4
#define MAX_SIZE_CBC_TEST 32

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

        uint8_t *cipher = NULL;
        uint32_t cipher_size;
        uint8_t *plain = NULL;
        uint32_t plain_size;

        printf("=== AES-128 ECB test ===\n");

        hex_str_to_bytes(vector_key, tmp_key, N_AES_KEY_SIZE);
        aes_key_init(tmp_key);

        for (uint8_t test_idx = 0; test_idx < N_ECB_TEST; ++test_idx) {
                printf("\n[TEST %d]\n", test_idx + 1);
                ptr_test = vector_text[test_idx];
                ptr_cipher = vector_cipher[test_idx];

                uint32_t input_size = strlen(ptr_test) / 2;
                hex_str_to_bytes(ptr_test, tmp_plain, input_size);
                uint32_t output_size = strlen(ptr_cipher) / 2;
                hex_str_to_bytes(ptr_cipher, tmp_cipher, output_size);

                print_hex_array("Plain text", tmp_plain, input_size);
                cipher = aes_encryption(tmp_plain, input_size, &cipher_size);
                printf("Encrypted size: %d\n", cipher_size);
                print_hex_array("Encryption", cipher, cipher_size);
                compare_result("Encryption", cipher, tmp_cipher, output_size);
                plain = aes_decryption(cipher, cipher_size, &plain_size);
                printf("Decrypted size: %d\n", plain_size);
                print_hex_array("Decryption", plain, plain_size);
                compare_result("Decryption", plain, tmp_plain, input_size);
                free(cipher);
                free(plain);
                cipher = plain = NULL;
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
        char *ptr_test, *ptr_cipher;

        uint8_t *cipher = NULL;
        uint32_t cipher_size;
        uint8_t *plain = NULL;
        uint32_t plain_size;

        printf("=== AES-128 CBC test ===\n");

        hex_str_to_bytes(vector_key, tmp_key, N_AES_KEY_SIZE);
        aes_key_init(tmp_key);

        for (uint8_t test_idx = 0; test_idx < N_ECB_TEST; ++test_idx) {
                printf("\n[TEST %d]\n", test_idx + 1);
                ptr_test = vector_text[test_idx];
                ptr_cipher = vector_cipher[test_idx];

                hex_str_to_bytes(vector_iv[test_idx], tmp_iv, N_AES_KEY_SIZE);
                aes_iv_init(tmp_iv);
                print_hex_array("Init vector", tmp_iv, N_AES_KEY_SIZE);

                uint32_t input_size = strlen(ptr_test) / 2;
                hex_str_to_bytes(ptr_test, tmp_plain, input_size);
                uint32_t output_size = strlen(ptr_cipher) / 2;
                hex_str_to_bytes(ptr_cipher, tmp_cipher, output_size);

                print_hex_array("Plain text", tmp_plain, input_size);
                cipher = aes_encryption(tmp_plain, input_size, &cipher_size);
                printf("Encrypted size: %d\n", cipher_size);
                print_hex_array("Encryption", cipher, cipher_size);
                compare_result("Encryption", cipher, tmp_cipher, output_size);
                plain = aes_decryption(cipher, cipher_size, &plain_size);
                printf("Decrypted size: %d\n", plain_size);
                print_hex_array("Decryption", plain, plain_size);
                compare_result("Decryption", plain, tmp_plain, input_size);
                free(cipher);
                free(plain);
                cipher = plain = NULL;
        }
}
#endif // TYPE_AES_CBC

int main(void)
{
#if defined(TYPE_AES_ECB)
        aes_test_ecb();
#endif
#if defined(TYPE_AES_CBC)
        aes_test_cbc();
#endif
        return 0;
}
