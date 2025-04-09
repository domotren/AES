#ifndef FORMAT_H_INCLUDED
#define FORMAT_H_INCLUDED

#include <stdint.h>

enum format_error {
        FORMAT_ERROR_INVALID_HEX = -3,
        FORMAT_ERROR_WRONG_STR_SIZE = -2,
        FORMAT_ERROR_INVALID_MEMORY = -1,
        FORMAT_OK = 0
};

extern enum format_error hex_str_to_bytes(char *src, uint8_t *dst,
                                          uint32_t array_size);

#endif // FORMAT_H_INCLUDED