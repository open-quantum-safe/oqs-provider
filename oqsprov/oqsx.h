// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 key handler.
 *
 * Code strongly inspired by OpenSSL crypto/ecx key handler but relocated here to have code within provider.
 *
 * ToDo: Review whether more functions are needed for sig, hybrids.
 */

/* Internal OQS functions for other submodules: not for application use */

#ifndef OQSX_H
# define OQSX_H

# include <stdatomic.h>
# include <openssl/opensslconf.h>

#  include <openssl/core.h>
#  include <openssl/e_os2.h>

/* Extras for OQS extension */

#define ON_ERR_SET_GOTO(condition, ret, code, gt) \
    if ((condition)) {                            \
        printf("ON_ERR_CONDITION: %d, setting code: %d\n", condition, code); fflush(stdout);   \
        (ret) = (code);                           \
        goto gt;                                  \
    }

#define ON_ERR_GOTO(condition, gt) \
    if ((condition)) {                        \
        printf("ON_ERR_CONDITION: %d\n", condition); fflush(stdout);   \
        goto gt;                              \
    }

#define ECP_NAME(secbits, oqsname) \
    (secbits == 128 ? "p256_" #oqsname "" : \
     secbits == 192 ? "p384_" #oqsname "" : \
                      "p521_" #oqsname "")
#define ECX_NAME(secbits, oqsname) \
    (secbits == 128 ? "x25519_" #oqsname "" : \
                        "x448_" #oqsname "")

typedef struct prov_oqs_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;         /* For all provider modules */
//    BIO_METHOD *corebiometh; // for the time being, do without BIO_METHOD
} PROV_OQS_CTX;

PROV_OQS_CTX *oqsx_newprovctx(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle);
void oqsx_freeprovctx(PROV_OQS_CTX *ctx);
# define PROV_OQS_LIBCTX_OF(provctx) (((PROV_OQS_CTX *)provctx)->libctx)

#include "oqs/oqs.h"

struct oqsx_kex_info_st {
    int nid_kex;
    int nid_kex_crv;
    int raw_key_support;
    size_t kex_length_public_key;
    size_t kex_length_private_key;
    size_t kex_length_secret;
};

typedef struct oqsx_kex_info_st OQSX_KEX_INFO;

struct oqsx_evp_ctx_st {
    EVP_PKEY_CTX *kex;
    EVP_PKEY *kexParam;
    const OQSX_KEX_INFO *kex_info;
};

typedef struct oqsx_evp_ctx_st OQSX_EVP_CTX;

typedef union {
    OQS_SIG *sig;
    OQS_KEM *kem;
} OQSX_QS_CTX;

struct oqsx_provider_ctx_st {
    OQSX_QS_CTX oqsx_qs_ctx;
    OQSX_EVP_CTX *oqsx_evp_ctx;
};

typedef struct oqsx_provider_ctx_st OQSX_PROVIDER_CTX;

enum oqsx_key_type_en {
    KEY_TYPE_SIG, KEY_TYPE_KEM, KEY_TYPE_ECP_HYB_KEM, KEY_TYPE_ECX_HYB_KEM
};

typedef enum oqsx_key_type_en OQSX_KEY_TYPE;

struct oqsx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    OQSX_KEY_TYPE keytype;
    OQSX_PROVIDER_CTX oqsx_provider_ctx;
    size_t numkeys;
    size_t privkeylen;
    size_t pubkeylen;
    char *oqs_name;
    char *tls_name;
    _Atomic int references;
    void **comp_privkey;
    void **comp_pubkey;
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
