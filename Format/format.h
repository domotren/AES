#ifndef _FORMAT_H_
#define _FORMAT_H_

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

enum format_error_type {
        FORMAT_ERROR_INVALID_HEX = -3,
        FORMAT_ERROR_WRONG_STR_SIZE = -2,
        FORMAT_ERROR_INVALID_MEMORY = -1,
        FORMAT_OK = 0
};

extern int hex_str_to_bytes(char *src, uint8_t *dst, uint32_t array_size);

#endif // _FORMAT_H_