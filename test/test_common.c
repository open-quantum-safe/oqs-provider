// SPDX-License-Identifier: Apache-2.0 AND MIT

#include "test_common.h"
#include <string.h>


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

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
int alg_is_enabled(const char *algname) {
    char *alglist = getenv("OQS_SKIP_TESTS");
    char *comma = NULL;
    char totest[200];

    if (alglist == NULL) return 1;

    while((comma = index(alglist, ','))) {
        memcpy(totest, alglist, MIN(200,comma-alglist));
        totest[comma-alglist]='\0';
        if (strstr(algname, totest)) return 0;
        alglist = comma+1;
    }
    return strstr(algname, alglist) == NULL;
}

