#ifndef OQSPROV_COMPAT_H
#define OQSPROV_COMPAT_H

#include <openssl/asn1.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Runtime-resolved wrappers for OpenSSL 4.1 deprecated ASN.1 APIs.
 *
 * These functions use dlsym/GetProcAddress to resolve the new OpenSSL 4.1
 * APIs at first call, falling back to legacy APIs if unavailable. This
 * preserves cross-runtime compatibility: a provider built against OpenSSL
 * 4.1 can still load and run against OpenSSL 3.x (and vice versa).
 */

/* Returns the length of an ASN1_STRING, using ASN1_STRING_get_length()
 * or ASN1_STRING_length_ex() if available at runtime, else ASN1_STRING_length()
 */
size_t oqsx_ASN1_STRING_length(const ASN1_STRING *x);

/* Sets data in an ASN1_STRING, using ASN1_STRING_set1_data() or
 * ASN1_STRING_set_data() if available at runtime, else ASN1_STRING_set() */
int oqsx_ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);

#ifdef __cplusplus
}
#endif

#endif /* OQSPROV_COMPAT_H */
