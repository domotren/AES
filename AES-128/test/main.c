
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

int main()
{
        uint8_t key[16] = {
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, \
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };
        uint8_t plain_text[16] = {
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, \
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a                
        };
        
        struct AES_ctx ctx;
        AES_init_ctx(&ctx, key);
        AES_ECB_encrypt(&ctx, plain_text);
        
        uint8_t i;
        for (i= 0; i< 16; ++i)
        {
                printf("0x%x ", plain_text[i]);
        }
        printf("\n");

        return 0;
}
