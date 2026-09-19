/*
 * Runtime compatibility layer for OpenSSL 4.1 deprecated ASN.1 APIs.
 *
 * All OpenSSL ASN.1 functions are resolved via dlsym/GetProcAddress at
 * first call. This avoids deprecation warnings at compile time (because
 * we never directly call deprecated declarations) and guarantees cross-
 * runtime compatibility (a provider built against 4.1 runs on 3.x).
 */

#include "oqsprov_compat.h"

#ifdef _WIN32
#include <windows.h>

static void *oqsx_dlsym(const char *name) {
    /* oqs-provider runs inside the OpenSSL process, so all libcrypto
     * symbols are already mapped in the current process address space. */
    return (void *)GetProcAddress(GetModuleHandle(NULL), name);
}

#else
#include <dlfcn.h>

static void *oqsx_dlsym(const char *name) { return dlsym(RTLD_DEFAULT, name); }

#endif

/* ---------------------------------------------------------------------- */
/* ASN1_STRING_length                                                     */
/* ---------------------------------------------------------------------- */

size_t oqsx_ASN1_STRING_length(const ASN1_STRING *x) {
    static int resolved = 0;
    static size_t (*fn)(const ASN1_STRING *) = NULL;

    if (!resolved) {
        /* Prefer new OpenSSL 4.1 APIs, fall back to legacy */
        fn = (size_t (*)(const ASN1_STRING *))oqsx_dlsym(
            "ASN1_STRING_get_length");
        if (!fn)
            fn = (size_t (*)(const ASN1_STRING *))oqsx_dlsym(
                "ASN1_STRING_length_ex");
        if (!fn)
            fn = (size_t (*)(const ASN1_STRING *))oqsx_dlsym(
                "ASN1_STRING_length");
        resolved = 1;
    }

    return fn(x);
}

/* ---------------------------------------------------------------------- */
/* ASN1_STRING_set                                                        */
/* ---------------------------------------------------------------------- */

int oqsx_ASN1_STRING_set(ASN1_STRING *str, const void *data, int len) {
    static int resolved = 0;
    static int (*fn)(ASN1_STRING *, const void *, int) = NULL;

    if (!resolved) {
        /* Prefer new OpenSSL 4.1 APIs, fall back to legacy */
        fn = (int (*)(ASN1_STRING *, const void *, int))oqsx_dlsym(
            "ASN1_STRING_set1_data");
        if (!fn)
            fn = (int (*)(ASN1_STRING *, const void *, int))oqsx_dlsym(
                "ASN1_STRING_set_data");
        if (!fn)
            fn = (int (*)(ASN1_STRING *, const void *, int))oqsx_dlsym(
                "ASN1_STRING_set");
        resolved = 1;
    }

    return fn(str, data, len);
}
