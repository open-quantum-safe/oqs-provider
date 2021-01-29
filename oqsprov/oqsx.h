/*
 * OQS OpenSSL 3 key handler.
 *
 * Code strongly inspired by OpenSSL crypto/ecx key handler but relocated here to have code within provider.
 *
 * ToDo: Review whether more functions are needed for sig, hybrids.
 */

/* Internal OQS functions for other submodules: not for application use */

#ifndef OSSL_PROVIDER_OQSX_H
# define OSSL_PROVIDER_OQSX_H
# include <openssl/opensslconf.h>

#  include <openssl/core.h>
#  include <openssl/e_os2.h>
#  include "internal/refcount.h"

typedef struct prov_oqs_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;         /* For all provider modules */
//    BIO_METHOD *corebiometh; // for the time being, do without BIO_METHOD
} PROV_OQS_CTX;


PROV_OQS_CTX *oqsx_newprovctx(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle);
void oqsx_freeprovctx(PROV_OQS_CTX *ctx);

#include "oqs/oqs.h"

typedef union {
    OQS_SIG *s;
    OQS_KEM *k;
} OQS_KEY;

struct oqsx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    unsigned int iskem:1;
    OQS_KEY key;
    size_t privkeylen;
    size_t pubkeylen;
    char *oqs_name;
    char *tls_name;
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
    void *privkey;
    void *pubkey;
};

typedef struct oqsx_key_st OQSX_KEY;


OQSX_KEY *oqsx_key_new(OSSL_LIB_CTX *libctx, char* oqs_name, char* tls_name, int is_kem, const char *propq);
int oqsx_key_allocate_keymaterial(OQSX_KEY *key);
void oqsx_key_free(OQSX_KEY *key);
int oqsx_key_up_ref(OQSX_KEY *key);
int oqsx_key_gen(OQSX_KEY *key);

/* Backend support */
int oqsx_public_from_private(OQSX_KEY *key);
int oqsx_key_fromdata(OQSX_KEY *oqsxk, const OSSL_PARAM params[],
                     int include_private);
int oqsx_key_parambits(OQSX_KEY *k);
int oqsx_key_maxsize(OQSX_KEY *k);
#endif
