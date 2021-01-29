/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL ecx key management.
 *
 * TBC: OQS license
 *
 * ToDo: Optimize macros; generate OQS-constants; testing in regular provider test harness
 */

/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>

#include <string.h>
/* For strcasecmp on Windows */
#include "e_os.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "openssl/param_build.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/oqsx.h"

// debugging
#define OQS_KM_PRINTF(a) if (getenv("OQSKM")) printf(a)
#define OQS_KM_PRINTF2(a, b) if (getenv("OQSKM")) printf(a, b)
#define OQS_KM_PRINTF3(a, b, c) if (getenv("OQSKM")) printf(a, b, c)

// our own error codes:
#define OQSPROV_UNEXPECTED_NULL   1

static OSSL_FUNC_keymgmt_gen_cleanup_fn oqsx_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn oqsx_load;
static OSSL_FUNC_keymgmt_get_params_fn oqsx_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn oqs_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn oqsx_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn oqsx_settable_params;
static OSSL_FUNC_keymgmt_has_fn oqsx_has;
static OSSL_FUNC_keymgmt_match_fn oqsx_match;
static OSSL_FUNC_keymgmt_import_fn oqsx_import;
static OSSL_FUNC_keymgmt_import_types_fn oqs_imexport_types;
static OSSL_FUNC_keymgmt_export_fn oqsx_export;
static OSSL_FUNC_keymgmt_export_types_fn oqs_imexport_types;

struct oqsx_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *propq;
    char *oqs_name;
    char *tls_name;
    int is_kem;
    int selection;
};

static int oqsx_has(const void *keydata, int selection)
{
    const OQSX_KEY *key = keydata;
    int ok = 0;

    OQS_KM_PRINTF("OQSKEYMGMT: has called\n");
    if (key != NULL) {
        /*
         * OQSX keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         */
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && key->pubkey != NULL;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && key->privkey != NULL;
    }
    return ok;
}

static int oqsx_match(const void *keydata1, const void *keydata2, int selection)
{
    const OQSX_KEY *key1 = keydata1;
    const OQSX_KEY *key2 = keydata2;
    int ok = 1;

    OQS_KM_PRINTF("OQSKEYMGMT: match called\n");

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && !strcmp(key1->oqs_name, key2->oqs_name);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if ((key1->privkey == NULL && key2->privkey != NULL)
                || (key1->privkey != NULL && key2->privkey == NULL)
                || strcmp(key1->oqs_name, key2->oqs_name))
            ok = 0;
        else
            ok = ok && (key1->privkey == NULL /* implies key2->privkey == NULL */
                        || CRYPTO_memcmp(key1->privkey, key2->privkey,
                                         key1->privkeylen) == 0);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if ((key1->pubkey!=NULL && key2->pubkey != NULL)
                || strcmp(key1->oqs_name, key2->oqs_name))
            ok = 0;
        else
            ok = ok && (key1->pubkey == NULL /* implies key2->haspubkey == NULL */
                        || CRYPTO_memcmp(key1->pubkey, key2->pubkey,
                                         key1->pubkeylen) == 0);
    }
    return ok;
}

static int oqsx_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    OQSX_KEY *key = keydata;
    int ok = 0;

    OQS_KM_PRINTF("OQSKEYMGMT: import called \n");
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, OQSPROV_UNEXPECTED_NULL);
        return ok;
    }

    if (((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0) &&
        (oqsx_key_fromdata(key, params, 1)))
        ok = 1;
    return ok;
}

static int oqsx_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    OQSX_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    OSSL_PARAM *p;
    int ret = 0;

    OQS_KM_PRINTF("OQSKEYMGMT: export called\n");
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, OQSPROV_UNEXPECTED_NULL);
        return 0;
    }

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        ERR_raise(ERR_LIB_USER, OQSPROV_UNEXPECTED_NULL);
        return 0;
    }

    if (((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0) ||
        ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)) {
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
            if (!OSSL_PARAM_set_octet_string(p, key->pubkey, key->pubkeylen))
                goto err;
        }
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
            if (!OSSL_PARAM_set_octet_string(p, key->privkey, key->privkeylen))
                goto err;
        }
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_BLD_free_params(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ret;
}

#define OQS_KEY_TYPES()                                                        \
OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),                     \
OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

static const OSSL_PARAM oqsx_key_types[] = {
    OQS_KEY_TYPES(),
    OSSL_PARAM_END
};
static const OSSL_PARAM *oqs_imexport_types(int selection)
{
    OQS_KM_PRINTF("OQSKEYMGMT: imexport called\n");
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return oqsx_key_types;
    return NULL;
}

static int oqsx_get_params(void *key, OSSL_PARAM params[])
{
    OQSX_KEY *oqsxk = key;
    OSSL_PARAM *p;

    OQS_KM_PRINTF("OQSKEYMGMT: get_params called\n");
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, oqsx_key_parambits(oqsxk)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, oqsx_key_parambits(oqsxk)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, oqsx_key_maxsize(oqsxk)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, oqsxk->pubkey, oqsxk->pubkeylen))
            return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, oqsxk->pubkey, oqsxk->pubkeylen))
            return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, oqsxk->privkey, oqsxk->privkeylen))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM oqsx_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OQS_KEY_TYPES(),
    OSSL_PARAM_END
};

static const OSSL_PARAM *oqs_gettable_params(void *provctx)
{
    OQS_KM_PRINTF("OQSKEYMGMT: gettable_params called\n");
    return oqsx_gettable_params;
}

static int set_property_query(OQSX_KEY *oqsxkey, const char *propq)
{
    OPENSSL_free(oqsxkey->propq);
    oqsxkey->propq = NULL;
    OQS_KM_PRINTF("OQSKEYMGMT: property_query called\n");
    if (propq != NULL) {
        oqsxkey->propq = OPENSSL_strdup(propq);
        if (oqsxkey->propq == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return 1;
}

static int oqsx_set_params(void *key, const OSSL_PARAM params[])
{
    OQSX_KEY *oqsxkey = key;
    const OSSL_PARAM *p;

    OQS_KM_PRINTF("OQSKEYMGMT: set_params called\n");
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        size_t used_len;
        if (p->data_size != oqsxkey->pubkeylen
                || !OSSL_PARAM_get_octet_string(p, &oqsxkey->pubkey, oqsxkey->pubkeylen,
                                                &used_len)) {
            return 0;
        }
        //OPENSSL_clear_free(oqsxkey->privkey, oqsxkey->privkeylen);
        //oqsxkey->privkey = NULL;
        //oqsxkey->pubkey = NULL; 
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
            || !set_property_query(oqsxkey, p->data)) {
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM oqs_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *oqsx_settable_params(void *provctx)
{
    OQS_KM_PRINTF("OQSKEYMGMT: settable_params called\n");
    return oqs_settable_params;
}

static void *oqsx_gen_init(void *provctx, int selection, char* oqs_name, int is_kem)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct oqsx_gen_ctx *gctx = NULL;

    OQS_KM_PRINTF2("OQSKEYMGMT: gen_init called for key %s\n", oqs_name);

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        gctx->oqs_name = OPENSSL_strdup(oqs_name);
        gctx->is_kem = is_kem;
        gctx->selection = selection;
    }
    return gctx;
}

static void *oqsx_genkey(struct oqsx_gen_ctx *gctx)
{
    OQSX_KEY *key;

    OQS_KM_PRINTF2("OQSKEYMGMT: gen called for %s\n", gctx->oqs_name);
    if (gctx == NULL)
        return NULL;
    if ((key = oqsx_key_new(gctx->libctx, gctx->oqs_name, NULL, gctx->is_kem, gctx->propq)) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (oqsx_key_gen(key)) {
       ERR_raise(ERR_LIB_USER, OQSPROV_UNEXPECTED_NULL);
       return NULL;
    }
    return key;
}

static void *oqsx_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct oqsx_gen_ctx *gctx = genctx;

    OQS_KM_PRINTF("OQSKEYMGMT: gen called\n");

    return oqsx_genkey(gctx);
}

static void oqsx_gen_cleanup(void *genctx)
{
    struct oqsx_gen_ctx *gctx = genctx;

    OQS_KM_PRINTF("OQSKEYMGMT: gen_cleanup called\n");
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

void *oqsx_load(const void *reference, size_t reference_sz)
{
    OQSX_KEY *key = NULL;

    OQS_KM_PRINTF("OQSKEYMGMT: load called\n");
    if (reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(OQSX_KEY **)reference;
        /* We grabbed, so we detach it */
        *(OQSX_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static const OSSL_PARAM *oqsx_gen_settable_params(void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static int oqsx_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct oqsx_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    OQS_KM_PRINTF("OQSKEYMGMT: gen_set_params called\n");
    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        const char *algname = (char*)p->data;

        gctx->tls_name = OPENSSL_strdup(algname);
    }
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        gctx->propq = OPENSSL_strdup(p->data);
        if (gctx->propq == NULL)
            return 0;
    }
    return 1;
}


///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_CONSTRUCTORS_START
static void *oqs_sig_default_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_default, "oqs_sig_default", 0, NULL);
}

static void *oqs_sig_default_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_default, 0);
}

static void *dilithium2_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_2, "dilithium2", 0, NULL);
}

static void *dilithium2_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_2, 0);
}
static void *dilithium3_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_3, "dilithium3", 0, NULL);
}

static void *dilithium3_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_3, 0);
}
static void *dilithium4_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_4, "dilithium4", 0, NULL);
}

static void *dilithium4_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_4, 0);
}

static void *falcon512_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_falcon_512, "falcon512", 0, NULL);
}

static void *falcon512_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_falcon_512, 0);
}
static void *falcon1024_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_falcon_1024, "falcon1024", 0, NULL);
}

static void *falcon1024_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_falcon_1024, 0);
}

static void *picnicl1full_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_picnic_L1_full, "picnicl1full", 0, NULL);
}

static void *picnicl1full_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_picnic_L1_full, 0);
}
static void *picnic3l1_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_picnic3_L1, "picnic3l1", 0, NULL);
}

static void *picnic3l1_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_picnic3_L1, 0);
}

static void *rainbowIclassic_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_rainbow_I_classic, "rainbowIclassic", 0, NULL);
}

static void *rainbowIclassic_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_rainbow_I_classic, 0);
}
static void *rainbowVclassic_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_rainbow_V_classic, "rainbowVclassic", 0, NULL);
}

static void *rainbowVclassic_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_rainbow_V_classic, 0);
}

static void *sphincsharaka128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_haraka_128f_robust, "sphincsharaka128frobust", 0, NULL);
}

static void *sphincsharaka128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_haraka_128f_robust, 0);
}

static void *sphincssha256128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_sha256_128f_robust, "sphincssha256128frobust", 0, NULL);
}

static void *sphincssha256128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_sha256_128f_robust, 0);
}

static void *sphincsshake256128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_shake256_128f_robust, "sphincsshake256128frobust", 0, NULL);
}

static void *sphincsshake256128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_shake256_128f_robust, 0);
}



static void *frodo640aes_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_frodokem_640_aes, "frodo640aes", 1, NULL);
}

static void *frodo640aes_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_frodokem_640_aes, 1);
} 

static void *frodo640shake_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_frodokem_640_shake, "frodo640shake", 1, NULL);
}

static void *frodo640shake_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_frodokem_640_shake, 1);
} 

static void *frodo976aes_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_frodokem_976_aes, "frodo976aes", 1, NULL);
}

static void *frodo976aes_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_frodokem_976_aes, 1);
} 

static void *frodo976shake_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_frodokem_976_shake, "frodo976shake", 1, NULL);
}

static void *frodo976shake_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_frodokem_976_shake, 1);
} 

static void *frodo1344aes_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_frodokem_1344_aes, "frodo1344aes", 1, NULL);
}

static void *frodo1344aes_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_frodokem_1344_aes, 1);
} 

static void *frodo1344shake_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_frodokem_1344_shake, "frodo1344shake", 1, NULL);
}

static void *frodo1344shake_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_frodokem_1344_shake, 1);
} 

static void *bike1l1cpa_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_bike1_l1_cpa, "bike1l1cpa", 1, NULL);
}

static void *bike1l1cpa_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_bike1_l1_cpa, 1);
} 

static void *bike1l3cpa_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_bike1_l3_cpa, "bike1l3cpa", 1, NULL);
}

static void *bike1l3cpa_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_bike1_l3_cpa, 1);
} 

static void *kyber512_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_kyber_512, "kyber512", 1, NULL);
}

static void *kyber512_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_kyber_512, 1);
} 

static void *kyber768_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_kyber_768, "kyber768", 1, NULL);
}

static void *kyber768_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_kyber_768, 1);
} 

static void *kyber1024_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_kyber_1024, "kyber1024", 1, NULL);
}

static void *kyber1024_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_kyber_1024, 1);
} 

static void *ntru_hps2048509_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_ntru_hps2048509, "ntru_hps2048509", 1, NULL);
}

static void *ntru_hps2048509_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_ntru_hps2048509, 1);
} 

static void *ntru_hps2048677_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_ntru_hps2048677, "ntru_hps2048677", 1, NULL);
}

static void *ntru_hps2048677_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_ntru_hps2048677, 1);
} 

static void *ntru_hps4096821_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_ntru_hps4096821, "ntru_hps4096821", 1, NULL);
}

static void *ntru_hps4096821_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_ntru_hps4096821, 1);
} 

static void *ntru_hrss701_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_ntru_hrss701, "ntru_hrss701", 1, NULL);
}

static void *ntru_hrss701_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_ntru_hrss701, 1);
} 

static void *lightsaber_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_saber_lightsaber, "lightsaber", 1, NULL);
}

static void *lightsaber_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_saber_lightsaber, 1);
} 

static void *saber_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_saber_saber, "saber", 1, NULL);
}

static void *saber_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_saber_saber, 1);
} 

static void *firesaber_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_saber_firesaber, "firesaber", 1, NULL);
}

static void *firesaber_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_saber_firesaber, 1);
} 

static void *sidhp434_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_sidh_p434, "sidhp434", 1, NULL);
}

static void *sidhp434_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_sidh_p434, 1);
} 

static void *sidhp503_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_sidh_p503, "sidhp503", 1, NULL);
}

static void *sidhp503_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_sidh_p503, 1);
} 

static void *sidhp610_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_sidh_p610, "sidhp610", 1, NULL);
}

static void *sidhp610_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_sidh_p610, 1);
} 

static void *sidhp751_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_sidh_p751, "sidhp751", 1, NULL);
}

static void *sidhp751_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_sidh_p751, 1);
} 

static void *sikep434_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_sike_p434, "sikep434", 1, NULL);
}

static void *sikep434_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_sike_p434, 1);
} 

static void *sikep503_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_sike_p503, "sikep503", 1, NULL);
}

static void *sikep503_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_sike_p503, 1);
} 

static void *sikep610_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_sike_p610, "sikep610", 1, NULL);
}

static void *sikep610_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_sike_p610, 1);
} 

static void *sikep751_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_sike_p751, "sikep751", 1, NULL);
}

static void *sikep751_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_sike_p751, 1);
} 

static void *bike1l1fo_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_bike1_l1_fo, "bike1l1fo", 1, NULL);
}

static void *bike1l1fo_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_bike1_l1_fo, 1);
} 

static void *bike1l3fo_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_bike1_l3_fo, "bike1l3fo", 1, NULL);
}

static void *bike1l3fo_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_bike1_l3_fo, 1);
} 

static void *kyber90s512_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_kyber_512_90s, "kyber90s512", 1, NULL);
}

static void *kyber90s512_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_kyber_512_90s, 1);
} 

static void *kyber90s768_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_kyber_768_90s, "kyber90s768", 1, NULL);
}

static void *kyber90s768_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_kyber_768_90s, 1);
} 

static void *kyber90s1024_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_kyber_1024_90s, "kyber90s1024", 1, NULL);
}

static void *kyber90s1024_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_kyber_1024_90s, 1);
} 

static void *hqc128_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_hqc_128, "hqc128", 1, NULL);
}

static void *hqc128_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_hqc_128, 1);
} 

static void *hqc192_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_hqc_192, "hqc192", 1, NULL);
}

static void *hqc192_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_hqc_192, 1);
} 

static void *hqc256_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_hqc_256, "hqc256", 1, NULL);
}

static void *hqc256_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_hqc_256, 1);
} 

static void *ntrulpr653_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_ntruprime_ntrulpr653, "ntrulpr653", 1, NULL);
}

static void *ntrulpr653_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_ntruprime_ntrulpr653, 1);
} 

static void *ntrulpr761_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_ntruprime_ntrulpr761, "ntrulpr761", 1, NULL);
}

static void *ntrulpr761_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_ntruprime_ntrulpr761, 1);
} 

static void *ntrulpr857_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_ntruprime_ntrulpr857, "ntrulpr857", 1, NULL);
}

static void *ntrulpr857_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_ntruprime_ntrulpr857, 1);
} 

static void *sntrup653_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_ntruprime_sntrup653, "sntrup653", 1, NULL);
}

static void *sntrup653_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_ntruprime_sntrup653, 1);
} 

static void *sntrup761_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_ntruprime_sntrup761, "sntrup761", 1, NULL);
}

static void *sntrup761_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_ntruprime_sntrup761, 1);
} 

static void *sntrup857_new_key(void *provctx)
{ 
    return oqsx_key_new(PROV_LIBCTX_OF(provctx), OQS_KEM_alg_ntruprime_sntrup857, "sntrup857", 1, NULL);
}

static void *sntrup857_gen_init(void *provctx, int selection)
{ 
    return oqsx_gen_init(provctx, selection, OQS_KEM_alg_ntruprime_sntrup857, 1);
} 

///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_CONSTRUCTORS_END

#define MAKE_KEYMGMT_FUNCTIONS(alg) \
\
    const OSSL_DISPATCH oqs_##alg##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))alg##_new_key }, \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))oqsx_key_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))oqsx_get_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))oqsx_settable_params },  \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))oqs_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))oqsx_set_params }, \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))oqsx_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))oqsx_match }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))oqsx_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))oqs_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))oqsx_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))oqs_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))alg##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))oqsx_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))oqsx_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))oqsx_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))oqsx_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))oqsx_load }, \
        { 0, NULL } \
    };


///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
MAKE_KEYMGMT_FUNCTIONS(oqs_sig_default)
MAKE_KEYMGMT_FUNCTIONS(dilithium2)
MAKE_KEYMGMT_FUNCTIONS(dilithium3)
MAKE_KEYMGMT_FUNCTIONS(dilithium4)
MAKE_KEYMGMT_FUNCTIONS(falcon512)
MAKE_KEYMGMT_FUNCTIONS(falcon1024)
MAKE_KEYMGMT_FUNCTIONS(picnicl1full)
MAKE_KEYMGMT_FUNCTIONS(picnic3l1)
MAKE_KEYMGMT_FUNCTIONS(rainbowIclassic)
MAKE_KEYMGMT_FUNCTIONS(rainbowVclassic)
MAKE_KEYMGMT_FUNCTIONS(sphincsharaka128frobust)
MAKE_KEYMGMT_FUNCTIONS(sphincssha256128frobust)
MAKE_KEYMGMT_FUNCTIONS(sphincsshake256128frobust)

MAKE_KEYMGMT_FUNCTIONS(frodo640aes)
MAKE_KEYMGMT_FUNCTIONS(frodo640shake)
MAKE_KEYMGMT_FUNCTIONS(frodo976aes)
MAKE_KEYMGMT_FUNCTIONS(frodo976shake)
MAKE_KEYMGMT_FUNCTIONS(frodo1344aes)
MAKE_KEYMGMT_FUNCTIONS(frodo1344shake)
MAKE_KEYMGMT_FUNCTIONS(bike1l1cpa)
MAKE_KEYMGMT_FUNCTIONS(bike1l3cpa)
MAKE_KEYMGMT_FUNCTIONS(kyber512)
MAKE_KEYMGMT_FUNCTIONS(kyber768)
MAKE_KEYMGMT_FUNCTIONS(kyber1024)
MAKE_KEYMGMT_FUNCTIONS(ntru_hps2048509)
MAKE_KEYMGMT_FUNCTIONS(ntru_hps2048677)
MAKE_KEYMGMT_FUNCTIONS(ntru_hps4096821)
MAKE_KEYMGMT_FUNCTIONS(ntru_hrss701)
MAKE_KEYMGMT_FUNCTIONS(lightsaber)
MAKE_KEYMGMT_FUNCTIONS(saber)
MAKE_KEYMGMT_FUNCTIONS(firesaber)
MAKE_KEYMGMT_FUNCTIONS(sidhp434)
MAKE_KEYMGMT_FUNCTIONS(sidhp503)
MAKE_KEYMGMT_FUNCTIONS(sidhp610)
MAKE_KEYMGMT_FUNCTIONS(sidhp751)
MAKE_KEYMGMT_FUNCTIONS(sikep434)
MAKE_KEYMGMT_FUNCTIONS(sikep503)
MAKE_KEYMGMT_FUNCTIONS(sikep610)
MAKE_KEYMGMT_FUNCTIONS(sikep751)
MAKE_KEYMGMT_FUNCTIONS(bike1l1fo)
MAKE_KEYMGMT_FUNCTIONS(bike1l3fo)
MAKE_KEYMGMT_FUNCTIONS(kyber90s512)
MAKE_KEYMGMT_FUNCTIONS(kyber90s768)
MAKE_KEYMGMT_FUNCTIONS(kyber90s1024)
MAKE_KEYMGMT_FUNCTIONS(hqc128)
MAKE_KEYMGMT_FUNCTIONS(hqc192)
MAKE_KEYMGMT_FUNCTIONS(hqc256)
MAKE_KEYMGMT_FUNCTIONS(ntrulpr653)
MAKE_KEYMGMT_FUNCTIONS(ntrulpr761)
MAKE_KEYMGMT_FUNCTIONS(ntrulpr857)
MAKE_KEYMGMT_FUNCTIONS(sntrup653)
MAKE_KEYMGMT_FUNCTIONS(sntrup761)
MAKE_KEYMGMT_FUNCTIONS(sntrup857)
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_END
