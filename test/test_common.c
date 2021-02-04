// SPDX-License-Identifier: Apache-2.0 AND MIT

#include "test_common.h"

void hexdump(const void *ptr, size_t len)
{
    const unsigned char *p = ptr;
    size_t i, j;

    for (i = 0; i < len; i += j) {
        for (j = 0; j < 16 && i + j < len; j++)
            printf("%s%02x", j? "" : " ", p[i + j]);
    }
    printf("\n");
}
