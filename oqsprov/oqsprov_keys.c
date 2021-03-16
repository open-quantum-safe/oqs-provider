// SPDX-License-Identifier: Apache-2.0 AND MIT

/* 
 * OQS OpenSSL 3 key handler.
 * 
 * Code strongly inspired by OpenSSL crypto/ec key handler but relocated here 
 * to have code within provider.
 *
 * TBC: Use/test in more than KEM and SIG cases.
 */

#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <string.h>
#include <assert.h>
#include "oqsx.h"

/// Provider code

PROV_OQS_CTX *oqsx_newprovctx(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle) {
    PROV_OQS_CTX * ret = OPENSSL_zalloc(sizeof(PROV_OQS_CTX));
    if (ret) {
       ret->libctx = libctx;
       ret->handle = handle;
    }
    return ret;
}

void oqsx_freeprovctx(PROV_OQS_CTX *ctx) {
    OPENSSL_free(ctx);
}

/// Key code

OQSX_KEY *oqsx_key_new(OSSL_LIB_CTX *libctx, char* oqs_name, char* tls_name, int primitive, const char *propq)
{
    OQSX_KEY *ret = OPENSSL_zalloc(sizeof(*ret));
    int ret2 = 0;

    if (ret == NULL) goto err;

    printf("Creating new %s key (type %d)\n", oqs_name, primitive);
    if (primitive == KEY_TYPE_KEM) {
        ret->primitive.kem = OQS_KEM_new(oqs_name);
        ret->privkeylen = ret->primitive.kem->length_secret_key;
        ret->pubkeylen = ret->primitive.kem->length_public_key;
        ret->keytype = KEY_TYPE_KEM;
    } else if (primitive == KEY_TYPE_SIG) {
        ret->primitive.sig = OQS_SIG_new(oqs_name);
        ret->privkeylen = ret->primitive.sig->length_secret_key;
        ret->pubkeylen = ret->primitive.sig->length_public_key;
        ret->keytype = KEY_TYPE_SIG;
    } else if (primitive == KEY_TYPE_HYB_KEM) {
        OQS_HYB_KEM* hybkem = OPENSSL_zalloc(sizeof(OQS_HYB_KEM));
        size_t kex_length_public_key = 0, kex_length_private_key = 0;

        ON_ERR_GOTO(!hybkem, err);

        hybkem->kem = OQS_KEM_new(oqs_name);
        ON_ERR_GOTO(!hybkem->kem, err);

        hybkem->kexParam = EVP_PKEY_new();
        ON_ERR_GOTO(!hybkem->kexParam, err);

        // TODO: don't hardcode X25519
        EVP_PKEY_set_type(hybkem->kexParam, NID_X25519);

        hybkem->kex = EVP_PKEY_CTX_new(hybkem->kexParam, NULL);
        ON_ERR_GOTO(!hybkem->kex, err);

        ret2 = EVP_PKEY_get_raw_public_key(hybkem->kexParam, NULL, &kex_length_public_key);
        ON_ERR_GOTO(ret2 <= 0 || kex_length_public_key == 0, err);

        ret2 = EVP_PKEY_get_raw_private_key(hybkem->kexParam, NULL, &kex_length_private_key);
        ON_ERR_GOTO(ret2 <= 0 || kex_length_private_key == 0, err);

        ret->primitive.hybkem = hybkem;
        ret->privkeylen = 4 + hybkem->kem->length_secret_key + 4 + kex_length_private_key;
        ret->pubkeylen = 4 + hybkem->kem->length_public_key + 4 + kex_length_public_key;
        ret->keytype = KEY_TYPE_HYB_KEM;
    } else goto err;

    ret->libctx = libctx;
    ret->references = 1;
    ret->tls_name = OPENSSL_strdup(tls_name);

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        if (ret->propq == NULL)
            goto err;
    }

    return ret;
err:
    ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(ret);
    return NULL;
}

void oqsx_key_free(OQSX_KEY *key)
{
    int refcnt;

    if (key == NULL)
        return;

    refcnt = atomic_fetch_sub_explicit(&key->references, 1,
                                       memory_order_relaxed) - 1;
    if (refcnt == 0)
        atomic_thread_fence(memory_order_acquire);
#ifndef NDEBUG
    fprintf(stderr, "%p:%4d:OQSX_KEY\n", (void*)key, refcnt);
#endif
    if (refcnt > 0)
        return;
#ifndef NDEBUG
    assert(refcnt == 0);
#endif

    OPENSSL_free(key->propq);
    OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
    OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
    if (key->keytype == KEY_TYPE_KEM)
        OQS_KEM_free(key->primitive.kem);
    else if (key->keytype == KEY_TYPE_HYB_KEM) {
        OQS_KEM_free(key->primitive.hybkem->kem);
        EVP_PKEY_CTX_free(key->primitive.hybkem->kex);
        EVP_PKEY_free(key->primitive.hybkem->kexParam);
    } else
        OQS_SIG_free(key->primitive.sig);
    OPENSSL_free(key);
}

int oqsx_key_up_ref(OQSX_KEY *key)
{
    int refcnt;

    refcnt = atomic_fetch_add_explicit(&key->references, 1,
                                       memory_order_relaxed) + 1;
#ifndef NDEBUG
    fprintf(stderr, "%p:%4d:OQSX_KEY\n", (void*)key, refcnt);
    assert(refcnt > 1);
#endif
    return (refcnt > 1);
}

int oqsx_key_allocate_keymaterial(OQSX_KEY *key)
{
    int ret = 0;

    if (!key->privkey) {
        key->privkey = OPENSSL_secure_zalloc(key->privkeylen);
        ON_ERR_SET_GOTO(!key->privkey, ret, 1, err);
    }
    if (!key->pubkey) {
        key->pubkey = OPENSSL_secure_zalloc(key->pubkeylen);
        ON_ERR_SET_GOTO(!key->pubkey, ret, 1, err);
    }
#if 0
    if (key->keytype == KEY_TYPE_HYB_KEM) {
        if (!key->privkeyhyb) {
            key->privkeyhyb = OPENSSL_secure_zalloc(key->privkeyhyblen);
            ON_ERR_SET_GOTO(!key->privkeyhyb, ret, 1, err);
        }
        if (!key->pubkeyhyb) {
            key->pubkeyhyb = OPENSSL_secure_zalloc(key->pubkeyhyblen);
            ON_ERR_SET_GOTO(!key->pubkeyhyb, ret, 1, err);
        }
    }
#endif
    err:
    return ret;
}

int oqsx_key_fromdata(OQSX_KEY *key, const OSSL_PARAM params[], int include_private)
{
    const OSSL_PARAM *p;

    printf("oqsx_key_fromdata\n");

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            printf("invalid data type\n");
            return 0;
        }
        OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
        key->privkey = OPENSSL_secure_malloc(p->data_size);
        if (key->privkey == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->privkey, p->data, p->data_size);
        key->privkeylen = p->data_size;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            printf("invalid data type\n");
            return 0;
        }
        OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
        key->pubkey = OPENSSL_secure_malloc(p->data_size);
        if (key->pubkey == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->pubkey, p->data, p->data_size);
        key->pubkeylen = p->data_size;
    }
    return 1;
}

int oqsx_key_gen(OQSX_KEY *key)
{
    int ret = 0, ret2 = 0;

    ret = oqsx_key_allocate_keymaterial(key);
    ON_ERR_GOTO(ret, err);

    if (key->keytype == KEY_TYPE_KEM) {
        ret = OQS_KEM_keypair(key->primitive.kem, key->pubkey, key->privkey);
        ON_ERR_GOTO(ret, err);
    } else if (key->keytype == KEY_TYPE_HYB_KEM) {
        OQS_HYB_KEM *hybkem = key->primitive.hybkem;
        OQS_KEM *kem = hybkem->kem;
        EVP_PKEY_CTX *kex = hybkem->kex;
        EVP_PKEY *pkey = NULL;

        size_t privkeykemlen = kem->length_secret_key, privkeykexlen = 0;
        size_t pubkeykemlen = kem->length_public_key, pubkeykexlen = 0;


        ret = OQS_KEM_keypair(hybkem->kem, key->pubkey + 4, key->privkey + 4);
        ON_ERR_GOTO(ret, err);

        ret2 = EVP_PKEY_keygen_init(kex);
        ON_ERR_SET_GOTO(ret2 != 1, ret, 10, err);
        ret2 = EVP_PKEY_keygen(kex, &pkey);
        ON_ERR_SET_GOTO(ret2 != 1, ret, 11, err);

        ret2 = EVP_PKEY_get_raw_public_key(pkey, key->pubkey + 4 + kem->length_public_key + 4, &pubkeykexlen);
        ON_ERR_SET_GOTO(ret2 <= 0, ret, 44, err);

        ret2 = EVP_PKEY_get_raw_private_key(pkey, key->privkey + 4 + kem->length_secret_key + 4, &privkeykexlen);
        ON_ERR_SET_GOTO(ret2 <= 0, ret, 45, err);

        ENCODE_UINT32((unsigned char *)key->pubkey, pubkeykemlen);
        ENCODE_UINT32((unsigned char *)key->pubkey + 4 + pubkeykemlen, pubkeykexlen);
        ENCODE_UINT32((unsigned char *)key->privkey, privkeykemlen);
        ENCODE_UINT32((unsigned char *)key->privkey + 4 + privkeykemlen, privkeykexlen);

    } else if (key->keytype == KEY_TYPE_SIG) {
        ret = OQS_SIG_keypair(key->primitive.sig, key->pubkey, key->privkey);
        ON_ERR_GOTO(ret, err);
    } else {
        ret = 1;
    }
    err:
    return ret;
}

int oqsx_key_parambits(OQSX_KEY *key) {
    if (key->keytype == KEY_TYPE_KEM)
        return 128+(key->primitive.kem->claimed_nist_level-1)/2*64;
    return 128+(key->primitive.sig->claimed_nist_level-1)/2*64;
}

int oqsx_key_maxsize(OQSX_KEY *key) {
    if (key->keytype == KEY_TYPE_KEM)
        return key->primitive.kem->length_shared_secret;
    return key->primitive.sig->length_signature;
}
