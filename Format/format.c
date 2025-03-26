
#include "format.h"

int hex_str_to_bytes(char *src, uint8_t *dst, size_t arr_size)
{
        if ((src == NULL) || (dst == NULL)) {
                return FORMAT_ERROR_INVALID_MEMORY;
        }

        size_t src_len = 0;
        while (src[src_len] != '\0') {
                ++src_len;
        }

        if (src_len != (arr_size * 2)) {
                return FORMAT_ERROR_WRONG_STR_SIZE;
        }

        size_t i;
        for (i = 0; i < arr_size; ++i) {
                size_t offset = 2 * i;
                if (!isxdigit(src[offset]) || !isxdigit(src[(offset + 1)])) {
                        return FORMAT_ERROR_INVALID_HEX;
                }
                sscanf(&(src[offset]), "%2hhx", &dst[i]);
        }

        return FORMAT_OK;
}
