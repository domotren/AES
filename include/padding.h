#ifndef PADDING_H_INCLUDED
#define PADDING_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void pkcs7_padding(uint8_t *data, uint64_t *data_size,
                          uint8_t block_size);

extern void pkcs7_unpadding(uint8_t *data, uint64_t *data_size,
                            uint8_t block_size);

#endif // PADDING_H_INCLUDED