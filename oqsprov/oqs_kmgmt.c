// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL ecx key management.
 *
 * ToDo: More testing in non-KEM cases
 */

#include <assert.h>

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "openssl/param_build.h"
#include "oqs_prov.h"

// stolen from openssl/crypto/param_build_set.c as ossl_param_build_set_octet_string not public API:

int oqsx_param_build_set_octet_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                      const char *key,
                                      const unsigned char *data,
                                      size_t data_len)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_octet_string(bld, key, data, data_len);

    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_octet_string(p, data, data_len);
    return 1;
}



#ifdef NDEBUG
#define OQS_KM_PRINTF(a)
#define OQS_KM_PRINTF2(a, b)
#define OQS_KM_PRINTF3(a, b, c)
#else
#define OQS_KM_PRINTF(a) if (getenv("OQSKM")) printf(a)
#define OQS_KM_PRINTF2(a, b) if (getenv("OQSKM")) printf(a, b)
#define OQS_KM_PRINTF3(a, b, c) if (getenv("OQSKM")) printf(a, b, c)
#endif // NDEBUG

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
    int primitive;
    int selection;
    int bit_security;
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

/*
 * Key matching has a problem in OQS world: OpenSSL assumes all keys to (also)
 * contain public key material (https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_eq.html).
 * This is not the case with decoded private keys: Not all algorithms permit re-creating
 * public key material from private keys (https://github.com/PQClean/PQClean/issues/415#issuecomment-910377682).
 * Thus we implement the following logic:
 * 1) Private keys are matched binary if available in both keys; only one key having private key material 
 *    will be considered a mismatch
 * 2) Public keys are matched binary if available in both keys; only one key having public key material
 *    will NOT be considered a mismatch if both private keys are present and match: The latter logic will
 *    only be triggered if domain parameter matching is requested to distinguish between a pure-play
 *    public key match/test and one checking OpenSSL-type "EVP-PKEY-equality". This is possible as domain
 *    parameters don't really play a role in OQS, so we consider them as a proxy for private key matching.
 */
 
static int oqsx_match(const void *keydata1, const void *keydata2, int selection)
{
    const OQSX_KEY *key1 = keydata1;
    const OQSX_KEY *key2 = keydata2;
    int ok = 1;

    OQS_KM_PRINTF3("OQSKEYMGMT: match called for %p and %p\n", keydata1, keydata2);
    OQS_KM_PRINTF2("OQSKEYMGMT: match called for selection %d\n", selection);

    if (((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)) {
        if ((key1->privkey == NULL && key2->privkey != NULL)
                || (key1->privkey != NULL && key2->privkey == NULL)
                || ((key1->tls_name!=NULL && key2->tls_name!=NULL) && strcmp(key1->tls_name, key2->tls_name)))
                ok = 0;
        else
            ok = ( (key1->privkey==NULL && key2->privkey==NULL) || ((key1->privkey != NULL) && CRYPTO_memcmp(key1->privkey, key2->privkey, key1->privkeylen) == 0) );
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if ((key1->pubkey == NULL && key2->pubkey != NULL) ||
            (key1->pubkey != NULL && key2->pubkey == NULL) ||
            ((key1->tls_name!=NULL && key2->tls_name!=NULL) && strcmp(key1->tls_name, key2->tls_name)))
            // special case now: If domain parameter matching requested, consider private key match sufficient:
            ok = ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) && 
                  (key1->privkey != NULL && key2->privkey != NULL) &&
                  (CRYPTO_memcmp(key1->privkey, key2->privkey, key1->privkeylen) == 0);
        else 
            ok = ok && ( (key1->pubkey==NULL && key2->pubkey==NULL) || ((key1->pubkey != NULL) && CRYPTO_memcmp(key1->pubkey, key2->pubkey, key1->pubkeylen) == 0) );
    }
    if (!ok) OQS_KM_PRINTF("OQSKEYMGMT: match failed!\n");
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

int oqsx_key_to_params(const OQSX_KEY *key, OSSL_PARAM_BLD *tmpl,
                  OSSL_PARAM params[], int include_private)
{
    int ret = 0;

    if (key == NULL)
        return 0;

    if (key->pubkey != NULL) {
        OSSL_PARAM *p = NULL;

        if (tmpl == NULL) {
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        }

        if (p != NULL || tmpl != NULL) {
            if (   key->pubkeylen == 0 
                || !oqsx_param_build_set_octet_string(tmpl, p,
                                                      OSSL_PKEY_PARAM_PUB_KEY,
                                                      key->pubkey, key->pubkeylen))
                goto err;
        }
    }
    if (key->privkey != NULL && include_private) {
        OSSL_PARAM *p = NULL;

        /*
         * Key import/export should never leak the bit length of the secret
         * scalar in the key. Conceptually. OQS is not production strength
         * so does not care. TBD.
         *
         */

        if (tmpl == NULL) {
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        }

        if (p != NULL || tmpl != NULL) {
            if (   key->privkeylen == 0 
                || !oqsx_param_build_set_octet_string(tmpl, p,
                                                      OSSL_PKEY_PARAM_PRIV_KEY,
                                                      key->privkey, key->privkeylen))
                goto err;
        }
    }
    ret = 1;
 err:
    return ret;
}

static int oqsx_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    OQSX_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    OSSL_PARAM *p;
    int ok = 1;

    OQS_KM_PRINTF("OQSKEYMGMT: export called\n");

    /*
     * In this implementation, only public and private keys can be exported, nothing else
     */
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, OQSPROV_UNEXPECTED_NULL);
        return 0;
    }

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        ERR_raise(ERR_LIB_USER, OQSPROV_UNEXPECTED_NULL);
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && oqsx_key_to_params(key, tmpl, NULL, include_private);
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        ok = 0;
        goto err;
    }

    ok = ok & param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ok;
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

// must handle param requests for KEM and SIG keys...
static int oqsx_get_params(void *key, OSSL_PARAM params[])
{
    OQSX_KEY *oqsxk = key;
    OSSL_PARAM *p;

    OQS_KM_PRINTF2("OQSKEYMGMT: get_params called for %s\n", params[0].key);
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, oqsx_key_secbits(oqsxk)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, oqsx_key_secbits(oqsxk)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, oqsx_key_maxsize(oqsxk)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) {
        // hybrid KEMs are special in that the classic length information shall not be passed out:
        if (oqsxk->keytype == KEY_TYPE_ECP_HYB_KEM || oqsxk->keytype == KEY_TYPE_ECX_HYB_KEM) {
            if (!OSSL_PARAM_set_octet_string(p, oqsxk->pubkey+SIZE_OF_UINT32, oqsxk->pubkeylen-SIZE_OF_UINT32))
                return 0;
        }
        else {
            if (!OSSL_PARAM_set_octet_string(p, oqsxk->pubkey, oqsxk->pubkeylen))
                return 0;
        }
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
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
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
        int classic_pubkey_len;
        if (oqsxkey->keytype == KEY_TYPE_ECP_HYB_KEM || oqsxkey->keytype == KEY_TYPE_ECX_HYB_KEM) {
            // classic key len already stored by key setup; only data needs to be filled in
            if (p->data_size != oqsxkey->pubkeylen-SIZE_OF_UINT32
                || !OSSL_PARAM_get_octet_string(p, &oqsxkey->comp_pubkey[0], oqsxkey->pubkeylen-SIZE_OF_UINT32,
                                                &used_len)) {
                return 0;
            }
        }
        else {
            if (p->data_size != oqsxkey->pubkeylen
                || !OSSL_PARAM_get_octet_string(p, &oqsxkey->pubkey, oqsxkey->pubkeylen,
                                                &used_len)) {
                return 0;
            }
        }
        OPENSSL_clear_free(oqsxkey->privkey, oqsxkey->privkeylen);
        oqsxkey->privkey = NULL;
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

static void *oqsx_gen_init(void *provctx, int selection, char* oqs_name, char* tls_name, int primitive, int bit_security)
{
    OSSL_LIB_CTX *libctx = PROV_OQS_LIBCTX_OF(provctx);
    struct oqsx_gen_ctx *gctx = NULL;

    OQS_KM_PRINTF2("OQSKEYMGMT: gen_init called for key %s \n", oqs_name);

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        gctx->oqs_name = OPENSSL_strdup(oqs_name);
        gctx->tls_name = OPENSSL_strdup(tls_name);
        gctx->primitive = primitive;
        gctx->selection = selection;
        gctx->bit_security = bit_security;
    }
    return gctx;
}

static void *oqsx_genkey(struct oqsx_gen_ctx *gctx)
{
    OQSX_KEY *key;

    OQS_KM_PRINTF3("OQSKEYMGMT: gen called for %s (%s)\n", gctx->oqs_name, gctx->tls_name);
    if (gctx == NULL)
        return NULL;
    if ((key = oqsx_key_new(gctx->libctx, gctx->oqs_name, gctx->tls_name, gctx->primitive, gctx->propq, gctx->bit_security)) == NULL) {
	OQS_KM_PRINTF2("OQSKM: Error generating key for %s\n", gctx->tls_name);
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
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
    OPENSSL_free(gctx->tls_name);
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

        OPENSSL_free(gctx->tls_name);
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
static void *dilithium2_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_2, "dilithium2", KEY_TYPE_SIG, NULL, 128);
}

static void *dilithium2_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_2, "dilithium2", 0, 128);
}
static void *p256_dilithium2_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_2, "p256_dilithium2", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *p256_dilithium2_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_2, "p256_dilithium2", KEY_TYPE_HYB_SIG, 128);
}
static void *rsa3072_dilithium2_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_2, "rsa3072_dilithium2", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *rsa3072_dilithium2_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_2, "rsa3072_dilithium2", KEY_TYPE_HYB_SIG, 128);
}
static void *dilithium3_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_3, "dilithium3", KEY_TYPE_SIG, NULL, 192);
}

static void *dilithium3_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_3, "dilithium3", 0, 192);
}
static void *p384_dilithium3_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_3, "p384_dilithium3", KEY_TYPE_HYB_SIG, NULL, 192);
}

static void *p384_dilithium3_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_3, "p384_dilithium3", KEY_TYPE_HYB_SIG, 192);
}
static void *dilithium5_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_5, "dilithium5", KEY_TYPE_SIG, NULL, 256);
}

static void *dilithium5_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_5, "dilithium5", 0, 256);
}
static void *p521_dilithium5_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_5, "p521_dilithium5", KEY_TYPE_HYB_SIG, NULL, 256);
}

static void *p521_dilithium5_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_5, "p521_dilithium5", KEY_TYPE_HYB_SIG, 256);
}
static void *dilithium2_aes_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_2_aes, "dilithium2_aes", KEY_TYPE_SIG, NULL, 128);
}

static void *dilithium2_aes_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_2_aes, "dilithium2_aes", 0, 128);
}
static void *p256_dilithium2_aes_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_2_aes, "p256_dilithium2_aes", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *p256_dilithium2_aes_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_2_aes, "p256_dilithium2_aes", KEY_TYPE_HYB_SIG, 128);
}
static void *rsa3072_dilithium2_aes_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_2_aes, "rsa3072_dilithium2_aes", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *rsa3072_dilithium2_aes_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_2_aes, "rsa3072_dilithium2_aes", KEY_TYPE_HYB_SIG, 128);
}
static void *dilithium3_aes_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_3_aes, "dilithium3_aes", KEY_TYPE_SIG, NULL, 192);
}

static void *dilithium3_aes_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_3_aes, "dilithium3_aes", 0, 192);
}
static void *p384_dilithium3_aes_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_3_aes, "p384_dilithium3_aes", KEY_TYPE_HYB_SIG, NULL, 192);
}

static void *p384_dilithium3_aes_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_3_aes, "p384_dilithium3_aes", KEY_TYPE_HYB_SIG, 192);
}
static void *dilithium5_aes_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_5_aes, "dilithium5_aes", KEY_TYPE_SIG, NULL, 256);
}

static void *dilithium5_aes_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_5_aes, "dilithium5_aes", 0, 256);
}
static void *p521_dilithium5_aes_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_dilithium_5_aes, "p521_dilithium5_aes", KEY_TYPE_HYB_SIG, NULL, 256);
}

static void *p521_dilithium5_aes_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_dilithium_5_aes, "p521_dilithium5_aes", KEY_TYPE_HYB_SIG, 256);
}

static void *falcon512_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_falcon_512, "falcon512", KEY_TYPE_SIG, NULL, 128);
}

static void *falcon512_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_falcon_512, "falcon512", 0, 128);
}
static void *p256_falcon512_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_falcon_512, "p256_falcon512", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *p256_falcon512_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_falcon_512, "p256_falcon512", KEY_TYPE_HYB_SIG, 128);
}
static void *rsa3072_falcon512_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_falcon_512, "rsa3072_falcon512", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *rsa3072_falcon512_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_falcon_512, "rsa3072_falcon512", KEY_TYPE_HYB_SIG, 128);
}
static void *falcon1024_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_falcon_1024, "falcon1024", KEY_TYPE_SIG, NULL, 256);
}

static void *falcon1024_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_falcon_1024, "falcon1024", 0, 256);
}
static void *p521_falcon1024_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_falcon_1024, "p521_falcon1024", KEY_TYPE_HYB_SIG, NULL, 256);
}

static void *p521_falcon1024_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_falcon_1024, "p521_falcon1024", KEY_TYPE_HYB_SIG, 256);
}

static void *picnicl1full_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_picnic_L1_full, "picnicl1full", KEY_TYPE_SIG, NULL, 128);
}

static void *picnicl1full_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_picnic_L1_full, "picnicl1full", 0, 128);
}
static void *p256_picnicl1full_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_picnic_L1_full, "p256_picnicl1full", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *p256_picnicl1full_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_picnic_L1_full, "p256_picnicl1full", KEY_TYPE_HYB_SIG, 128);
}
static void *rsa3072_picnicl1full_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_picnic_L1_full, "rsa3072_picnicl1full", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *rsa3072_picnicl1full_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_picnic_L1_full, "rsa3072_picnicl1full", KEY_TYPE_HYB_SIG, 128);
}
static void *picnic3l1_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_picnic3_L1, "picnic3l1", KEY_TYPE_SIG, NULL, 128);
}

static void *picnic3l1_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_picnic3_L1, "picnic3l1", 0, 128);
}
static void *p256_picnic3l1_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_picnic3_L1, "p256_picnic3l1", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *p256_picnic3l1_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_picnic3_L1, "p256_picnic3l1", KEY_TYPE_HYB_SIG, 128);
}
static void *rsa3072_picnic3l1_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_picnic3_L1, "rsa3072_picnic3l1", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *rsa3072_picnic3l1_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_picnic3_L1, "rsa3072_picnic3l1", KEY_TYPE_HYB_SIG, 128);
}

static void *rainbowVclassic_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_rainbow_V_classic, "rainbowVclassic", KEY_TYPE_SIG, NULL, 256);
}

static void *rainbowVclassic_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_rainbow_V_classic, "rainbowVclassic", 0, 256);
}
static void *p521_rainbowVclassic_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_rainbow_V_classic, "p521_rainbowVclassic", KEY_TYPE_HYB_SIG, NULL, 256);
}

static void *p521_rainbowVclassic_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_rainbow_V_classic, "p521_rainbowVclassic", KEY_TYPE_HYB_SIG, 256);
}

static void *sphincsharaka128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_haraka_128f_robust, "sphincsharaka128frobust", KEY_TYPE_SIG, NULL, 128);
}

static void *sphincsharaka128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_haraka_128f_robust, "sphincsharaka128frobust", 0, 128);
}
static void *p256_sphincsharaka128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_haraka_128f_robust, "p256_sphincsharaka128frobust", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *p256_sphincsharaka128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_haraka_128f_robust, "p256_sphincsharaka128frobust", KEY_TYPE_HYB_SIG, 128);
}
static void *rsa3072_sphincsharaka128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_haraka_128f_robust, "rsa3072_sphincsharaka128frobust", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *rsa3072_sphincsharaka128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_haraka_128f_robust, "rsa3072_sphincsharaka128frobust", KEY_TYPE_HYB_SIG, 128);
}

static void *sphincssha256128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_sha256_128f_robust, "sphincssha256128frobust", KEY_TYPE_SIG, NULL, 128);
}

static void *sphincssha256128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_sha256_128f_robust, "sphincssha256128frobust", 0, 128);
}
static void *p256_sphincssha256128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_sha256_128f_robust, "p256_sphincssha256128frobust", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *p256_sphincssha256128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_sha256_128f_robust, "p256_sphincssha256128frobust", KEY_TYPE_HYB_SIG, 128);
}
static void *rsa3072_sphincssha256128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_sha256_128f_robust, "rsa3072_sphincssha256128frobust", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *rsa3072_sphincssha256128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_sha256_128f_robust, "rsa3072_sphincssha256128frobust", KEY_TYPE_HYB_SIG, 128);
}

static void *sphincsshake256128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_shake256_128f_robust, "sphincsshake256128frobust", KEY_TYPE_SIG, NULL, 128);
}

static void *sphincsshake256128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_shake256_128f_robust, "sphincsshake256128frobust", 0, 128);
}
static void *p256_sphincsshake256128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_shake256_128f_robust, "p256_sphincsshake256128frobust", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *p256_sphincsshake256128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_shake256_128f_robust, "p256_sphincsshake256128frobust", KEY_TYPE_HYB_SIG, 128);
}
static void *rsa3072_sphincsshake256128frobust_new_key(void *provctx)
{
    return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), OQS_SIG_alg_sphincs_shake256_128f_robust, "rsa3072_sphincsshake256128frobust", KEY_TYPE_HYB_SIG, NULL, 128);
}

static void *rsa3072_sphincsshake256128frobust_gen_init(void *provctx, int selection)
{
    return oqsx_gen_init(provctx, selection, OQS_SIG_alg_sphincs_shake256_128f_robust, "rsa3072_sphincsshake256128frobust", KEY_TYPE_HYB_SIG, 128);
}

///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_CONSTRUCTORS_END

#define MAKE_SIG_KEYMGMT_FUNCTIONS(alg) \
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

#define MAKE_KEM_KEYMGMT_FUNCTIONS(tokalg, tokoqsalg, bit_security) \
\
    static void *tokalg##_new_key(void *provctx) \
    { \
        return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), tokoqsalg, "" #tokalg "", KEY_TYPE_KEM, NULL, bit_security); \
    }                                                 \
                                                      \
    static void *tokalg##_gen_init(void *provctx, int selection) \
    { \
        return oqsx_gen_init(provctx, selection, tokoqsalg, "" #tokalg "", KEY_TYPE_KEM, bit_security); \
    }                                                 \
                                                      \
    const OSSL_DISPATCH oqs_##tokalg##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tokalg##_new_key }, \
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
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))tokalg##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))oqsx_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))oqsx_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))oqsx_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))oqsx_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))oqsx_load }, \
        { 0, NULL } \
    }; \
                                                      \
    static void *ecp_##tokalg##_new_key(void *provctx) \
    { \
        return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), tokoqsalg, ECP_NAME(bit_security, tokalg), KEY_TYPE_ECP_HYB_KEM, NULL, bit_security); \
    } \
                                                      \
    static void *ecp_##tokalg##_gen_init(void *provctx, int selection) \
    { \
        return oqsx_gen_init(provctx, selection, tokoqsalg, ECP_NAME(bit_security, tokalg), KEY_TYPE_ECP_HYB_KEM, bit_security); \
    } \
                                                      \
    const OSSL_DISPATCH oqs_ecp_##tokalg##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ecp_##tokalg##_new_key }, \
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
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ecp_##tokalg##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))oqsx_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))oqsx_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))oqsx_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))oqsx_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))oqsx_load }, \
        { 0, NULL } \
    }; \
                                                      \
    static void *ecx_##tokalg##_new_key(void *provctx) \
    { \
        return oqsx_key_new(PROV_OQS_LIBCTX_OF(provctx), tokoqsalg, ECX_NAME(bit_security, tokalg), KEY_TYPE_ECX_HYB_KEM, NULL, bit_security); \
    } \
                                                      \
    static void *ecx_##tokalg##_gen_init(void *provctx, int selection) \
    { \
        return oqsx_gen_init(provctx, selection, tokoqsalg, ECX_NAME(bit_security, tokalg), KEY_TYPE_ECX_HYB_KEM, bit_security); \
    } \
                                                      \
    const OSSL_DISPATCH oqs_ecx_##tokalg##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ecx_##tokalg##_new_key }, \
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
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ecx_##tokalg##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))oqsx_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))oqsx_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))oqsx_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))oqsx_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))oqsx_load }, \
        { 0, NULL } \
    };

///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
MAKE_SIG_KEYMGMT_FUNCTIONS(dilithium2)
MAKE_SIG_KEYMGMT_FUNCTIONS(p256_dilithium2)
MAKE_SIG_KEYMGMT_FUNCTIONS(rsa3072_dilithium2)
MAKE_SIG_KEYMGMT_FUNCTIONS(dilithium3)
MAKE_SIG_KEYMGMT_FUNCTIONS(p384_dilithium3)
MAKE_SIG_KEYMGMT_FUNCTIONS(dilithium5)
MAKE_SIG_KEYMGMT_FUNCTIONS(p521_dilithium5)
MAKE_SIG_KEYMGMT_FUNCTIONS(dilithium2_aes)
MAKE_SIG_KEYMGMT_FUNCTIONS(p256_dilithium2_aes)
MAKE_SIG_KEYMGMT_FUNCTIONS(rsa3072_dilithium2_aes)
MAKE_SIG_KEYMGMT_FUNCTIONS(dilithium3_aes)
MAKE_SIG_KEYMGMT_FUNCTIONS(p384_dilithium3_aes)
MAKE_SIG_KEYMGMT_FUNCTIONS(dilithium5_aes)
MAKE_SIG_KEYMGMT_FUNCTIONS(p521_dilithium5_aes)
MAKE_SIG_KEYMGMT_FUNCTIONS(falcon512)
MAKE_SIG_KEYMGMT_FUNCTIONS(p256_falcon512)
MAKE_SIG_KEYMGMT_FUNCTIONS(rsa3072_falcon512)
MAKE_SIG_KEYMGMT_FUNCTIONS(falcon1024)
MAKE_SIG_KEYMGMT_FUNCTIONS(p521_falcon1024)
MAKE_SIG_KEYMGMT_FUNCTIONS(picnicl1full)
MAKE_SIG_KEYMGMT_FUNCTIONS(p256_picnicl1full)
MAKE_SIG_KEYMGMT_FUNCTIONS(rsa3072_picnicl1full)
MAKE_SIG_KEYMGMT_FUNCTIONS(picnic3l1)
MAKE_SIG_KEYMGMT_FUNCTIONS(p256_picnic3l1)
MAKE_SIG_KEYMGMT_FUNCTIONS(rsa3072_picnic3l1)
MAKE_SIG_KEYMGMT_FUNCTIONS(rainbowVclassic)
MAKE_SIG_KEYMGMT_FUNCTIONS(p521_rainbowVclassic)
MAKE_SIG_KEYMGMT_FUNCTIONS(sphincsharaka128frobust)
MAKE_SIG_KEYMGMT_FUNCTIONS(p256_sphincsharaka128frobust)
MAKE_SIG_KEYMGMT_FUNCTIONS(rsa3072_sphincsharaka128frobust)
MAKE_SIG_KEYMGMT_FUNCTIONS(sphincssha256128frobust)
MAKE_SIG_KEYMGMT_FUNCTIONS(p256_sphincssha256128frobust)
MAKE_SIG_KEYMGMT_FUNCTIONS(rsa3072_sphincssha256128frobust)
MAKE_SIG_KEYMGMT_FUNCTIONS(sphincsshake256128frobust)
MAKE_SIG_KEYMGMT_FUNCTIONS(p256_sphincsshake256128frobust)
MAKE_SIG_KEYMGMT_FUNCTIONS(rsa3072_sphincsshake256128frobust)

MAKE_KEM_KEYMGMT_FUNCTIONS(frodo640aes, OQS_KEM_alg_frodokem_640_aes, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(frodo640shake, OQS_KEM_alg_frodokem_640_shake, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(frodo976aes, OQS_KEM_alg_frodokem_976_aes, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(frodo976shake, OQS_KEM_alg_frodokem_976_shake, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(frodo1344aes, OQS_KEM_alg_frodokem_1344_aes, 256)
MAKE_KEM_KEYMGMT_FUNCTIONS(frodo1344shake, OQS_KEM_alg_frodokem_1344_shake, 256)
MAKE_KEM_KEYMGMT_FUNCTIONS(kyber512, OQS_KEM_alg_kyber_512, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(kyber768, OQS_KEM_alg_kyber_768, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(kyber1024, OQS_KEM_alg_kyber_1024, 256)
MAKE_KEM_KEYMGMT_FUNCTIONS(ntru_hps2048509, OQS_KEM_alg_ntru_hps2048509, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(ntru_hps2048677, OQS_KEM_alg_ntru_hps2048677, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(ntru_hps4096821, OQS_KEM_alg_ntru_hps4096821, 256)
MAKE_KEM_KEYMGMT_FUNCTIONS(ntru_hps40961229, OQS_KEM_alg_ntru_hps40961229, 256)
MAKE_KEM_KEYMGMT_FUNCTIONS(ntru_hrss701, OQS_KEM_alg_ntru_hrss701, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(ntru_hrss1373, OQS_KEM_alg_ntru_hrss1373, 256)
MAKE_KEM_KEYMGMT_FUNCTIONS(lightsaber, OQS_KEM_alg_saber_lightsaber, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(saber, OQS_KEM_alg_saber_saber, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(firesaber, OQS_KEM_alg_saber_firesaber, 256)
MAKE_KEM_KEYMGMT_FUNCTIONS(bikel1, OQS_KEM_alg_bike_l1, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(bikel3, OQS_KEM_alg_bike_l3, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(kyber90s512, OQS_KEM_alg_kyber_512_90s, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(kyber90s768, OQS_KEM_alg_kyber_768_90s, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(kyber90s1024, OQS_KEM_alg_kyber_1024_90s, 256)
MAKE_KEM_KEYMGMT_FUNCTIONS(hqc128, OQS_KEM_alg_hqc_128, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(hqc192, OQS_KEM_alg_hqc_192, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(hqc256, OQS_KEM_alg_hqc_256, 256)
MAKE_KEM_KEYMGMT_FUNCTIONS(ntrulpr653, OQS_KEM_alg_ntruprime_ntrulpr653, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(ntrulpr761, OQS_KEM_alg_ntruprime_ntrulpr761, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(ntrulpr857, OQS_KEM_alg_ntruprime_ntrulpr857, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(ntrulpr1277, OQS_KEM_alg_ntruprime_ntrulpr1277, 256)
MAKE_KEM_KEYMGMT_FUNCTIONS(sntrup653, OQS_KEM_alg_ntruprime_sntrup653, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(sntrup761, OQS_KEM_alg_ntruprime_sntrup761, 128)
MAKE_KEM_KEYMGMT_FUNCTIONS(sntrup857, OQS_KEM_alg_ntruprime_sntrup857, 192)
MAKE_KEM_KEYMGMT_FUNCTIONS(sntrup1277, OQS_KEM_alg_ntruprime_sntrup1277, 256)
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_END
