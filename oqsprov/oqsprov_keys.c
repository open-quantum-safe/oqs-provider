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

static const OQS_KEX_INFO nids_ecp[] = {
        { EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65 , 121, 32}, // level 1
        { EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65 , 121, 32}, // level 2
        { EVP_PKEY_EC, NID_secp384r1       , 0, 97 , 167, 48}, // level 3
        { EVP_PKEY_EC, NID_secp384r1       , 0, 97 , 167, 48}, // level 4
        { EVP_PKEY_EC, NID_secp521r1       , 0, 133, 223, 66}  // level 5
};

static const OQS_KEX_INFO nids_ecx[] = {
        { EVP_PKEY_X25519, 0, 1, 32, 32, 32}, // level 1
        { EVP_PKEY_X25519, 0, 1, 32, 32, 32}, // level 2
        { EVP_PKEY_X448,   0, 1, 56, 56, 56}, // level 3
        { EVP_PKEY_X448,   0, 1, 56, 56, 56}, // level 4
        { EVP_PKEY_X448,   0, 1, 56, 56, 56}  // level 5
};

static int oqshybkem_init_ecp(int nistlevel, OQS_HYB_KEM *hybkem, OQS_KEX_INFO *kex_info)
{
    int ret = 1;

    *kex_info = nids_ecp[nistlevel - 1];

    hybkem->kex = EVP_PKEY_CTX_new_id(kex_info->nid_kex, NULL);
    ON_ERR_GOTO(!hybkem->kex, err);

    ret = EVP_PKEY_paramgen_init(hybkem->kex);
    ON_ERR_GOTO(ret <= 0, err);

    ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(hybkem->kex, kex_info->nid_kex_crv);
    ON_ERR_GOTO(ret <= 0, err);

    ret = EVP_PKEY_paramgen(hybkem->kex, &hybkem->kexParam);
    ON_ERR_GOTO(ret <= 0 || !hybkem->kexParam, err);

    err:
    return ret;
}

static int oqshybkem_init_ecx(int nistlevel, OQS_HYB_KEM *hybkem, OQS_KEX_INFO *kex_info)
{
    int ret = 1;

    *kex_info = nids_ecx[nistlevel - 1];

    hybkem->kexParam = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!hybkem->kexParam, ret, -1, err);

    ret = EVP_PKEY_set_type(hybkem->kexParam, kex_info->nid_kex);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    hybkem->kex = EVP_PKEY_CTX_new(hybkem->kexParam, NULL);
    ON_ERR_SET_GOTO(!hybkem->kex, ret, -1, err);

    err:
    return ret;
}

static const int (*init_kex_fun[])(int, OQS_HYB_KEM *, OQS_KEX_INFO *) = {
        oqshybkem_init_ecp,
        oqshybkem_init_ecx
};

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

    if (primitive == KEY_TYPE_SIG) {
        ret->primitive.sig = OQS_SIG_new(oqs_name);
        ret->privkeylen = ret->primitive.sig->length_secret_key;
        ret->pubkeylen = ret->primitive.sig->length_public_key;
        ret->keytype = KEY_TYPE_SIG;
    } else if (primitive == KEY_TYPE_KEM) {
        ret->primitive.kem = OQS_KEM_new(oqs_name);
        ret->privkeylen = ret->primitive.kem->length_secret_key;
        ret->pubkeylen = ret->primitive.kem->length_public_key;
        ret->keytype = KEY_TYPE_KEM;
    } else if (primitive == KEY_TYPE_ECX_HYB_KEM || primitive == KEY_TYPE_ECP_HYB_KEM) {
        OQS_HYB_KEM *hybkem = OPENSSL_zalloc(sizeof(OQS_HYB_KEM));
        ON_ERR_GOTO(!hybkem, err);

        hybkem->kem = OQS_KEM_new(oqs_name);
        ON_ERR_GOTO(!hybkem->kem, err);

        ret2 = (init_kex_fun[primitive - KEY_TYPE_ECP_HYB_KEM])
                (hybkem->kem->claimed_nist_level, hybkem, &hybkem->kex_info);
        ON_ERR_GOTO(ret2 <= 0 || !hybkem->kexParam || !hybkem->kex, err);

        ret->primitive.hybkem = hybkem;
        ret->privkeylen = 4 + hybkem->kem->length_secret_key + 4 + hybkem->kex_info.kex_length_private_key;
        ret->pubkeylen = 4 + hybkem->kem->length_public_key + 4 + hybkem->kex_info.kex_length_public_key;
        ret->keytype = primitive;
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
    else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM) {
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

#if 0
static void printhex(const char* title, unsigned char* c, size_t clen) {
    printf("%s = ", title);
    for (int i = 0; i < clen; ++i) {
        printf("%02x", c[i]);
    }
    printf("\n");
}
#endif

int oqsx_key_gen(OQSX_KEY *key)
{
    int ret = 0, ret2 = 0;

    ret = oqsx_key_allocate_keymaterial(key);
    ON_ERR_GOTO(ret, err);

    if (key->keytype == KEY_TYPE_KEM) {
        ret = OQS_KEM_keypair(key->primitive.kem, key->pubkey, key->privkey);
        ON_ERR_GOTO(ret, err);
    } else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM) {
        OQS_HYB_KEM *hybkem = key->primitive.hybkem;
        // Free at errhyb:
        EVP_PKEY_CTX *kgctx = NULL;
        EVP_PKEY *pkey = NULL;
        unsigned char *pubkeykex_encoded = NULL;

        size_t privkeykemlen = hybkem->kem->length_secret_key, privkeykexlen = 0;
        size_t pubkeykemlen = hybkem->kem->length_public_key, pubkeykexlen = 0;

        ret = OQS_KEM_keypair(hybkem->kem, key->pubkey + 4, key->privkey + 4);
        ON_ERR_GOTO(ret, errhyb);

        kgctx = EVP_PKEY_CTX_new(hybkem->kexParam, NULL);
        ON_ERR_SET_GOTO(!kgctx, ret, -1, errhyb);

        ret2 = EVP_PKEY_keygen_init(kgctx);
        ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
        ret2 = EVP_PKEY_keygen(kgctx, &pkey);
        ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);


        // TODO: is there a way to use pre-allocated space for the encoded key?
        pubkeykexlen = EVP_PKEY_get1_encoded_public_key(pkey, &pubkeykex_encoded);
        ON_ERR_SET_GOTO(pubkeykexlen <= 0 || !pubkeykex_encoded, ret, -1, errhyb);

        memcpy(key->pubkey + 4 + hybkem->kem->length_public_key + 4, pubkeykex_encoded, pubkeykexlen);


        if (hybkem->kex_info.raw_key_support) {
            ret2 = EVP_PKEY_get_raw_private_key(pkey, key->privkey + 4 + hybkem->kem->length_secret_key + 4, &privkeykexlen);
            ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
        } else {
            // TODO: Workaround for potential bug in OSSL3
            // i2d_PrivateKey returns incorrect size. We ignore it because the encoded data seems correct.
            // One could instead point to the already allocated private key once a bug for this is fixed
            // See: https://github.com/openssl/openssl/issues/14655
            unsigned char *pkey_enc = NULL;
            i2d_PrivateKey(pkey, &pkey_enc);
            ON_ERR_SET_GOTO(!pkey_enc, ret, -1, errhyb);
            //ON_ERR_SET_GOTO(pkey_enclen != hybkem->kex_nid.kex_length_private_key, ret, -1, err);

            privkeykexlen = hybkem->kex_info.kex_length_private_key;

            memcpy(key->privkey + 4 + hybkem->kem->length_secret_key + 4, pkey_enc, hybkem->kex_info.kex_length_private_key);
            OPENSSL_clear_free(pkey_enc, privkeykexlen);
        }

        ENCODE_UINT32((unsigned char *)key->pubkey, pubkeykemlen);
        ENCODE_UINT32((unsigned char *)key->pubkey + 4 + pubkeykemlen, pubkeykexlen);
        ENCODE_UINT32((unsigned char *)key->privkey, privkeykemlen);
        ENCODE_UINT32((unsigned char *)key->privkey + 4 + privkeykemlen, privkeykexlen);

        errhyb:
        EVP_PKEY_CTX_free(kgctx);
        EVP_PKEY_free(pkey);
        OPENSSL_free(pubkeykex_encoded);
        ON_ERR_GOTO(ret <= 0, err);
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
    else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM)
        return 128+(key->primitive.hybkem->kem->claimed_nist_level-1)/2*64;
    return 128+(key->primitive.sig->claimed_nist_level-1)/2*64;
}

int oqsx_key_maxsize(OQSX_KEY *key) {
    if (key->keytype == KEY_TYPE_KEM)
        return key->primitive.kem->length_shared_secret;
    else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM)
        return key->primitive.hybkem->kex_info.kex_length_secret + key->primitive.hybkem->kem->length_shared_secret;
    else return key->primitive.sig->length_signature;
}
