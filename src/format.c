
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "format.h"

// function to remove whitespace in string, reserved.
#if 0
static void trim_space(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
}
#endif

enum format_error hex_str_to_bytes(char *src, uint8_t *dst, uint32_t arr_size)
{
        if ((src == NULL) || (dst == NULL)) {
                return FORMAT_ERROR_INVALID_MEMORY;
        }

        uint32_t src_len = 0;
        while (src[src_len] != '\0') {
                ++src_len;
        }

        if (src_len != (arr_size * 2)) {
                return FORMAT_ERROR_WRONG_STR_SIZE;
        }

        for (uint32_t i = 0; i < arr_size; ++i) {
                uint32_t offset = 2 * i;
                if (!isxdigit(src[offset]) || !isxdigit(src[(offset + 1)])) {
                        return FORMAT_ERROR_INVALID_HEX;
                }
                sscanf(&(src[offset]), "%2hhx", &dst[i]);
        }

        return FORMAT_OK;
}
