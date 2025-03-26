
#include "padding.h"
#include <stdio.h>

void pkcs7_padding(uint8_t *data, uint32_t *data_size, uint8_t block_size) {
        uint8_t padding_size;
        padding_size = block_size - (*data_size % block_size);
        memset((data + *data_size), padding_size, padding_size);
        *data_size += padding_size;
}

void pkcs7_unpadding(uint8_t *data, uint32_t *data_size, uint8_t block_size) {
        uint8_t final_data = data[*data_size - 1];
        uint32_t padding_idx;

        if (*data_size % block_size == 0) {
                padding_idx = *data_size - block_size;
        } else {
                padding_idx = (*data_size / block_size) * block_size;
        }

        for (uint8_t i = padding_idx; i < *data_size; ++i) {
                if (*(data + i) != final_data) {
                        return;
                }
        }

        *data_size -= padding_idx;
}
