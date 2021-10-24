// SPDX-License-Identifier: Apache-2.0 AND MIT

/* 
 * OQS OpenSSL 3 key handler.
 * 
 * Code strongly inspired by OpenSSL crypto/ec key handler but relocated here 
 * to have code within provider.
 *
 */

#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string.h>
#include <assert.h>
#include "oqs_prov.h"

#ifdef NDEBUG
#define OQS_KEY_PRINTF(a)
#define OQS_KEY_PRINTF2(a, b)
#define OQS_KEY_PRINTF3(a, b, c)
#else
#define OQS_KEY_PRINTF(a) if (getenv("OQSKEY")) printf(a)
#define OQS_KEY_PRINTF2(a, b) if (getenv("OQSKEY")) printf(a, b)
#define OQS_KEY_PRINTF3(a, b, c) if (getenv("OQSKEY")) printf(a, b, c)
#endif // NDEBUG

typedef enum {
    KEY_OP_PUBLIC,
    KEY_OP_PRIVATE,
    KEY_OP_KEYGEN
} oqsx_key_op_t;

/// NID/name table

typedef struct {
    int nid;
    char* tlsname;
    char* oqsname;
    int secbits;
} oqs_nid_name_t;

///// OQS_TEMPLATE_FRAGMENT_OQSNAMES_START
#define NID_TABLE_LEN 39

static oqs_nid_name_t nid_names[NID_TABLE_LEN] = {
       { 0, "dilithium2", OQS_SIG_alg_dilithium_2, 128 },
       { 0, "p256_dilithium2", OQS_SIG_alg_dilithium_2, 128 },
       { 0, "rsa3072_dilithium2", OQS_SIG_alg_dilithium_2, 128 },
       { 0, "dilithium3", OQS_SIG_alg_dilithium_3, 192 },
       { 0, "p384_dilithium3", OQS_SIG_alg_dilithium_3, 192 },
       { 0, "dilithium5", OQS_SIG_alg_dilithium_5, 256 },
       { 0, "p521_dilithium5", OQS_SIG_alg_dilithium_5, 256 },
       { 0, "dilithium2_aes", OQS_SIG_alg_dilithium_2_aes, 128 },
       { 0, "p256_dilithium2_aes", OQS_SIG_alg_dilithium_2_aes, 128 },
       { 0, "rsa3072_dilithium2_aes", OQS_SIG_alg_dilithium_2_aes, 128 },
       { 0, "dilithium3_aes", OQS_SIG_alg_dilithium_3_aes, 192 },
       { 0, "p384_dilithium3_aes", OQS_SIG_alg_dilithium_3_aes, 192 },
       { 0, "dilithium5_aes", OQS_SIG_alg_dilithium_5_aes, 256 },
       { 0, "p521_dilithium5_aes", OQS_SIG_alg_dilithium_5_aes, 256 },
       { 0, "falcon512", OQS_SIG_alg_falcon_512, 128 },
       { 0, "p256_falcon512", OQS_SIG_alg_falcon_512, 128 },
       { 0, "rsa3072_falcon512", OQS_SIG_alg_falcon_512, 128 },
       { 0, "falcon1024", OQS_SIG_alg_falcon_1024, 256 },
       { 0, "p521_falcon1024", OQS_SIG_alg_falcon_1024, 256 },
       { 0, "picnicl1full", OQS_SIG_alg_picnic_L1_full, 128 },
       { 0, "p256_picnicl1full", OQS_SIG_alg_picnic_L1_full, 128 },
       { 0, "rsa3072_picnicl1full", OQS_SIG_alg_picnic_L1_full, 128 },
       { 0, "picnic3l1", OQS_SIG_alg_picnic3_L1, 128 },
       { 0, "p256_picnic3l1", OQS_SIG_alg_picnic3_L1, 128 },
       { 0, "rsa3072_picnic3l1", OQS_SIG_alg_picnic3_L1, 128 },
       { 0, "rainbowIclassic", OQS_SIG_alg_rainbow_I_classic, 128 },
       { 0, "p256_rainbowIclassic", OQS_SIG_alg_rainbow_I_classic, 128 },
       { 0, "rsa3072_rainbowIclassic", OQS_SIG_alg_rainbow_I_classic, 128 },
       { 0, "rainbowVclassic", OQS_SIG_alg_rainbow_V_classic, 256 },
       { 0, "p521_rainbowVclassic", OQS_SIG_alg_rainbow_V_classic, 256 },
       { 0, "sphincsharaka128frobust", OQS_SIG_alg_sphincs_haraka_128f_robust, 128 },
       { 0, "p256_sphincsharaka128frobust", OQS_SIG_alg_sphincs_haraka_128f_robust, 128 },
       { 0, "rsa3072_sphincsharaka128frobust", OQS_SIG_alg_sphincs_haraka_128f_robust, 128 },
       { 0, "sphincssha256128frobust", OQS_SIG_alg_sphincs_sha256_128f_robust, 128 },
       { 0, "p256_sphincssha256128frobust", OQS_SIG_alg_sphincs_sha256_128f_robust, 128 },
       { 0, "rsa3072_sphincssha256128frobust", OQS_SIG_alg_sphincs_sha256_128f_robust, 128 },
       { 0, "sphincsshake256128frobust", OQS_SIG_alg_sphincs_shake256_128f_robust, 128 },
       { 0, "p256_sphincsshake256128frobust", OQS_SIG_alg_sphincs_shake256_128f_robust, 128 },
       { 0, "rsa3072_sphincsshake256128frobust", OQS_SIG_alg_sphincs_shake256_128f_robust, 128 },
///// OQS_TEMPLATE_FRAGMENT_OQSNAMES_END
};

int oqs_set_nid(char* tlsname, int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (!strcmp(nid_names[i].tlsname, tlsname)) {
          nid_names[i].nid = nid;
          return 1;
      }
   }
   return 0;
}

static int get_secbits(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].secbits;
   }
   return 0; 
}

static char* get_oqsname(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].oqsname;
   }
   return 0; 
}

/// Provider code

PROV_OQS_CTX *oqsx_newprovctx(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle, BIO_METHOD *bm) {
    PROV_OQS_CTX * ret = OPENSSL_zalloc(sizeof(PROV_OQS_CTX));
    if (ret) {
       ret->libctx = libctx;
       ret->handle = handle;
       ret->corebiometh = bm;
    }
    return ret;
}

void oqsx_freeprovctx(PROV_OQS_CTX *ctx) {
    OPENSSL_free(ctx);
}


void oqsx_key_set0_libctx(OQSX_KEY *key, OSSL_LIB_CTX *libctx)
{
    key->libctx = libctx;
}

// convenience function creating OQSX keys from nids (only for sigs; hybrids TBD)
static OQSX_KEY *oqsx_key_new_from_nid(OSSL_LIB_CTX *libctx, const char *propq, int id) {
    return oqsx_key_new(libctx, get_oqsname(id), (char *)OBJ_nid2sn(id), KEY_TYPE_SIG, propq, get_secbits(id)); 
}


OQSX_KEY *oqsx_key_op(const X509_ALGOR *palg,
                      const unsigned char *p, int plen,
                      oqsx_key_op_t op,
                      OSSL_LIB_CTX *libctx, const char *propq)
{
    OQSX_KEY *key = NULL;
    void **privkey, **pubkey;
    int id;

    if (op != KEY_OP_KEYGEN) {
        if (palg != NULL) {
            int ptype;

            /* Algorithm parameters must be absent */
            X509_ALGOR_get0(NULL, &ptype, NULL, palg);
            if (ptype != V_ASN1_UNDEF) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                return 0;
            }
            id = OBJ_obj2nid(palg->algorithm);
        }

        if (p == NULL || id == EVP_PKEY_NONE) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return 0;
        }
    }

    key = oqsx_key_new_from_nid(libctx, propq, id);
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (op == KEY_OP_PUBLIC) {
        if (key->pubkeylen != plen) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            goto err;
        }
        key->pubkey = OPENSSL_secure_zalloc(key->pubkeylen); 
        if (key->pubkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(key->pubkey, p, plen);
    } else {
        if (key->privkeylen+key->pubkeylen != plen) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            goto err;
        }
        key->privkey = OPENSSL_secure_zalloc(key->privkeylen); 
        key->pubkey = OPENSSL_secure_zalloc(key->pubkeylen); 
        if (key->privkey == NULL || key->pubkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(key->privkey, p, key->privkeylen);
        memcpy(key->pubkey, p+key->privkeylen, key->pubkeylen);
    }

    return key;

 err:
    oqsx_key_free(key);
    return NULL;
}

OQSX_KEY *oqsx_key_from_x509pubkey(const X509_PUBKEY *xpk,
                              OSSL_LIB_CTX *libctx, const char *propq)
{
    const unsigned char *p;
    int plen;
    X509_ALGOR *palg;
    OQSX_KEY* oqsx = NULL;

    if (!xpk || (!X509_PUBKEY_get0_param(NULL, &p, &plen, &palg, xpk))) {
        return NULL;
    }
    oqsx = oqsx_key_op(palg, p, plen, KEY_OP_PUBLIC, libctx, propq);
    return oqsx;
}

OQSX_KEY *oqsx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                              OSSL_LIB_CTX *libctx, const char *propq)
{
    OQSX_KEY *oqsx = NULL;
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8inf))
        return 0;

    oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
    if (oct == NULL) {
        p = NULL;
        plen = 0;
    } else {
        p = ASN1_STRING_get0_data(oct);
        plen = ASN1_STRING_length(oct);
    }

    oqsx = oqsx_key_op(palg, p, plen, KEY_OP_PRIVATE,
                       libctx, propq);
    ASN1_OCTET_STRING_free(oct);
    return oqsx;
}

/// Key code

static const OQSX_KEX_INFO nids_ecp[] = {
        { EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65 , 121, 32}, // 128 bit
        { EVP_PKEY_EC, NID_secp384r1       , 0, 97 , 167, 48}, // 192 bit
        { EVP_PKEY_EC, NID_secp521r1       , 0, 133, 223, 66}  // 256 bit
};

static const OQSX_KEX_INFO nids_ecx[] = {
        { EVP_PKEY_X25519, 0, 1, 32, 32, 32}, // 128 bit
        { EVP_PKEY_X448,   0, 1, 56, 56, 56}, // 192 bit
        { 0,               0, 0,  0,  0,  0}  // 256 bit
};

static int oqshybkem_init_ecp(int bit_security, OQSX_EVP_CTX *evp_ctx)
{
    int ret = 1;
    int idx = (bit_security - 128) / 64;
    ON_ERR_GOTO(idx < 0 || idx > 2, err);

    evp_ctx->kex_info = &nids_ecp[idx];

    evp_ctx->kex = EVP_PKEY_CTX_new_id(evp_ctx->kex_info->nid_kex, NULL);
    ON_ERR_GOTO(!evp_ctx->kex, err);

    ret = EVP_PKEY_paramgen_init(evp_ctx->kex);
    ON_ERR_GOTO(ret <= 0, err);

    ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx->kex, evp_ctx->kex_info->nid_kex_crv);
    ON_ERR_GOTO(ret <= 0, err);

    ret = EVP_PKEY_paramgen(evp_ctx->kex, &evp_ctx->kexParam);
    ON_ERR_GOTO(ret <= 0 || !evp_ctx->kexParam, err);

    err:
    return ret;
}

static int oqshybkem_init_ecx(int bit_security, OQSX_EVP_CTX *evp_ctx)
{
    int ret = 1;
    int idx = (bit_security - 128) / 64;
    ON_ERR_GOTO(idx < 0 || idx > 2, err);

    evp_ctx->kex_info = &nids_ecx[idx];

    evp_ctx->kexParam = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!evp_ctx->kexParam, ret, -1, err);

    ret = EVP_PKEY_set_type(evp_ctx->kexParam, evp_ctx->kex_info->nid_kex);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    evp_ctx->kex = EVP_PKEY_CTX_new(evp_ctx->kexParam, NULL);
    ON_ERR_SET_GOTO(!evp_ctx->kex, ret, -1, err);

    err:
    return ret;
}

static const int (*init_kex_fun[])(int, OQSX_EVP_CTX *) = {
        oqshybkem_init_ecp,
        oqshybkem_init_ecx
};

OQSX_KEY *oqsx_key_new(OSSL_LIB_CTX *libctx, char* oqs_name, char* tls_name, int primitive, const char *propq, int bit_security)
{
    OQSX_KEY *ret = OPENSSL_zalloc(sizeof(*ret));
    int ret2 = 0;

    if (ret == NULL) goto err;

    if (oqs_name == NULL) {
        OQS_KEY_PRINTF("OQSX_KEY: Fatal error: No OQS key name provided:\n");
        goto err;
    }

    if (primitive == KEY_TYPE_SIG) {
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ret->oqsx_provider_ctx.oqsx_qs_ctx.sig = OQS_SIG_new(oqs_name);
        ret->privkeylen = ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_secret_key;
        ret->pubkeylen = ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key;
        ret->keytype = KEY_TYPE_SIG;
    } else if (primitive == KEY_TYPE_KEM) {
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = OQS_KEM_new(oqs_name);
        ret->privkeylen = ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key;
        ret->pubkeylen = ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
        ret->keytype = KEY_TYPE_KEM;
    } else if (primitive == KEY_TYPE_ECX_HYB_KEM || primitive == KEY_TYPE_ECP_HYB_KEM) {
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = OQS_KEM_new(oqs_name);
        ON_ERR_GOTO(!ret->oqsx_provider_ctx.oqsx_qs_ctx.kem, err);
        OQSX_EVP_CTX *evp_ctx = OPENSSL_zalloc(sizeof(OQSX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

        ret2 = (init_kex_fun[primitive - KEY_TYPE_ECP_HYB_KEM])
                (bit_security, evp_ctx);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->kexParam || !evp_ctx->kex, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(2 * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(2 * sizeof(void *));
        ret->privkeylen = ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key + evp_ctx->kex_info->kex_length_private_key;
        ret->pubkeylen = ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key + evp_ctx->kex_info->kex_length_public_key;
        ret->oqsx_provider_ctx.oqsx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
    } else goto err;

    ret->libctx = libctx;
    ret->references = 1;
    ret->tls_name = OPENSSL_strdup(tls_name);
    ret->bit_security = bit_security;

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        if (ret->propq == NULL)
            goto err;
    }

    OQS_KEY_PRINTF2("OQSX_KEY: new key created: %p\n", ret);
    return ret;
err:
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
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
    OQS_KEY_PRINTF3("%p:%4d:OQSX_KEY\n", (void*)key, refcnt);
    if (refcnt > 0)
        return;
#ifndef NDEBUG
    assert(refcnt == 0);
#endif

    OPENSSL_free(key->propq);
    OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
    OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
    OPENSSL_free(key->comp_pubkey);
    OPENSSL_free(key->comp_privkey);
    if (key->keytype == KEY_TYPE_KEM)
        OQS_KEM_free(key->oqsx_provider_ctx.oqsx_qs_ctx.kem);
    else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM) {
        OQS_KEM_free(key->oqsx_provider_ctx.oqsx_qs_ctx.kem);
        EVP_PKEY_CTX_free(key->oqsx_provider_ctx.oqsx_evp_ctx->kex);
        EVP_PKEY_free(key->oqsx_provider_ctx.oqsx_evp_ctx->kexParam);
        OPENSSL_free(key->oqsx_provider_ctx.oqsx_evp_ctx);
    } else
        OQS_SIG_free(key->oqsx_provider_ctx.oqsx_qs_ctx.sig);
    OPENSSL_free(key);
}

int oqsx_key_up_ref(OQSX_KEY *key)
{
    int refcnt;

    refcnt = atomic_fetch_add_explicit(&key->references, 1,
                                       memory_order_relaxed) + 1;
    OQS_KEY_PRINTF3("%p:%4d:OQSX_KEY\n", (void*)key, refcnt);
#ifndef NDEBUG
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

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return 0;
        }
        if (key->privkeylen != p->data_size) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
        key->privkey = OPENSSL_secure_malloc(p->data_size);
        if (key->privkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->privkey, p->data, p->data_size);
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            OQS_KEY_PRINTF("invalid data type\n");
            return 0;
        }
        if (key->pubkeylen != p->data_size) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
        key->pubkey = OPENSSL_secure_malloc(p->data_size);
        if (key->pubkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->pubkey, p->data, p->data_size);
    }
    return 1;
}

static int oqsx_key_gen_oqs_kem(OQS_KEM *ctx, unsigned char *pubkey, unsigned char *privkey)
{
    return OQS_KEM_keypair(ctx, pubkey, privkey);
}

static int oqsx_key_gen_oqs_sig(OQS_SIG *ctx, unsigned char *pubkey, unsigned char *privkey)
{
    return OQS_SIG_keypair(ctx, pubkey, privkey);
}

static int oqsx_key_gen_evp_kex(OQSX_EVP_CTX *ctx, unsigned char *pubkey, unsigned char *privkey)
{
    int ret = 0, ret2 = 0;

    // Free at errhyb:
    EVP_PKEY_CTX *kgctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkeykex_encoded = NULL;

    size_t pubkeykexlen = 0;

    kgctx = EVP_PKEY_CTX_new(ctx->kexParam, NULL);
    ON_ERR_SET_GOTO(!kgctx, ret, -1, errhyb);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    ret2 = EVP_PKEY_keygen(kgctx, &pkey);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);

    // TODO: If available, use preallocated memory
    pubkeykexlen = EVP_PKEY_get1_encoded_public_key(pkey, &pubkeykex_encoded);
    ON_ERR_SET_GOTO(pubkeykexlen <= 0 || !pubkeykex_encoded, ret, -1, errhyb);

    memcpy(pubkey, pubkeykex_encoded, pubkeykexlen);

    if (ctx->kex_info->raw_key_support) {
        size_t privkeykexlen = ctx->kex_info->kex_length_private_key;
        ret2 = EVP_PKEY_get_raw_private_key(pkey, privkey, &privkeykexlen);
        ON_ERR_SET_GOTO(ret2 <= 0 || privkeykexlen != ctx->kex_info->kex_length_private_key, ret, -1, errhyb);
    } else {
        unsigned char *pkey_enc = privkey;
        int privkeykexlen = i2d_PrivateKey(pkey, &pkey_enc);
        ON_ERR_SET_GOTO(!pkey_enc || privkeykexlen != (int) ctx->kex_info->kex_length_private_key, ret, -1, errhyb);
    }

    errhyb:
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkeykex_encoded);

    return ret;
}

int oqsx_key_gen(OQSX_KEY *key)
{
    int ret = 0;

    if (key->privkey == NULL || key->pubkey == NULL) {
        ret = oqsx_key_allocate_keymaterial(key);
        ON_ERR_GOTO(ret, err);
    }

    if (key->keytype == KEY_TYPE_KEM) {
        key->comp_privkey[0] = key->privkey;
        key->comp_pubkey[0] = key->pubkey;
        ret = oqsx_key_gen_oqs_kem(key->oqsx_provider_ctx.oqsx_qs_ctx.kem, key->comp_pubkey[0], key->comp_privkey[0]);
        ON_ERR_GOTO(ret, err);
    } else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM) {
        key->comp_privkey[0] = key->privkey;
        key->comp_pubkey[0] = key->pubkey;
        key->comp_privkey[1] = key->privkey + key->oqsx_provider_ctx.oqsx_evp_ctx->kex_info->kex_length_private_key;
        key->comp_pubkey[1] = key->pubkey + key->oqsx_provider_ctx.oqsx_evp_ctx->kex_info->kex_length_public_key;
        ret = oqsx_key_gen_evp_kex(key->oqsx_provider_ctx.oqsx_evp_ctx, key->comp_pubkey[0], key->comp_privkey[0]);
        ON_ERR_GOTO(ret, err);
        ret = oqsx_key_gen_oqs_kem(key->oqsx_provider_ctx.oqsx_qs_ctx.kem, key->comp_pubkey[1], key->comp_privkey[1]);
        ON_ERR_GOTO(ret, err);
    } else if (key->keytype == KEY_TYPE_SIG) {
        key->comp_privkey[0] = key->privkey;
        key->comp_pubkey[0] = key->pubkey;
        ret = oqsx_key_gen_oqs_sig(key->oqsx_provider_ctx.oqsx_qs_ctx.sig, key->pubkey, key->privkey);
        ON_ERR_GOTO(ret, err);
    } else {
        ret = 1;
    }
    err:
    return ret;
}

int oqsx_key_parambits(OQSX_KEY *key) {
    return key->bit_security;
}

int oqsx_key_maxsize(OQSX_KEY *key) {
    if (key->keytype == KEY_TYPE_KEM)
        return key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret;
    else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM)
        return key->oqsx_provider_ctx.oqsx_evp_ctx->kex_info->kex_length_secret + key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret;
    else return key->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature;
}
