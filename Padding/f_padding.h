#ifndef _PADDING_H_
#define _PADDING_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void pkcs7_padding(uint8_t *data, uint32_t *data_size,
                          uint8_t block_size);

extern void pkcs7_unpadding(uint8_t *data, uint32_t *data_size,
                            uint8_t block_size);

#endif // _PADDING_H_