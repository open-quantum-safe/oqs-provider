/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL DSA signature provider.
 * 
 * TBC: OQS license
 *
 * ToDo: Everything: This is just a template that needs to be completed with 
 * OQS calls.
 * Significant hurdle: Signature providers of new algorithms are not utilized 
 * properly in OpenSSL3 yet -> Integration won't be seamless and probably 
 * requires quite some (upstream) OpenSSL3 dev investment.
 */

/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#include "oqs/sig.h"

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "prov/oqsx.h"

// our own error codes:
#define OQSPROV_R_INVALID_DIGEST                            1
#define OQSPROV_R_INVALID_SIZE                              2
#define OQSPROV_R_INVALID_KEY                               3

// TBD: Review what we really need/want: For now go with OSSL settings:
#define OSSL_MAX_NAME_SIZE 50
#define OSSL_MAX_PROPQUERY_SIZE     256 /* Property query strings */

// internal, but useful OSSL define:
# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

// debugging
#define OQS_SIG_PRINTF(a) if (getenv("OQSSIG")) printf(a)
#define OQS_SIG_PRINTF2(a, b) if (getenv("OQSSIG")) printf(a, b)
#define OQS_SIG_PRINTF3(a, b, c) if (getenv("OQSSIG")) printf(a, b, c)

static OSSL_FUNC_signature_newctx_fn oqs_sig_newctx;
static OSSL_FUNC_signature_sign_init_fn oqs_sig_sign_init;
static OSSL_FUNC_signature_verify_init_fn oqs_sig_verify_init;
static OSSL_FUNC_signature_sign_fn oqs_sig_sign;
static OSSL_FUNC_signature_verify_fn oqs_sig_verify;
static OSSL_FUNC_signature_digest_sign_init_fn oqs_sig_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn oqs_sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn oqs_sig_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn oqs_sig_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn oqs_sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn oqs_sig_digest_verify_final;
static OSSL_FUNC_signature_freectx_fn oqs_sig_freectx;
static OSSL_FUNC_signature_dupctx_fn oqs_sig_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn oqs_sig_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn oqs_sig_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn oqs_sig_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn oqs_sig_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn oqs_sig_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn oqs_sig_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn oqs_sig_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn oqs_sig_settable_ctx_md_params;

// OIDS:
static int get_oqs_oid(unsigned char* oidbuf, const char *oqs_name) {
///// OQS_TEMPLATE_FRAGMENT_SIG_OIDS_START
   if (!strcmp(OQS_SIG_alg_default, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.9999.1.1", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_dilithium_2, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.6.1.4.1.2.267.6.4.3", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_dilithium_3, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.6.1.4.1.2.267.6.5.4", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_dilithium_4, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.6.1.4.1.2.267.6.6.5", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_falcon_512, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.9999.3.1", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_falcon_1024, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.9999.3.4", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_picnic_L1_full, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.6.1.4.1.311.89.2.1.7", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_picnic3_L1, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.6.1.4.1.311.89.2.1.21", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_rainbow_I_classic, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.9999.5.1.1", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_rainbow_V_classic, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.9999.5.3.1", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_sphincs_haraka_128f_robust, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.9999.6.1.1", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_sphincs_sha256_128f_robust, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.9999.6.4.1", 1), &oidbuf);
   else
   if (!strcmp(OQS_SIG_alg_sphincs_shake256_128f_robust, oqs_name))
       return i2d_ASN1_OBJECT(OBJ_txt2obj("1.3.9999.6.7.1", 1), &oidbuf);
   else
///// OQS_TEMPLATE_FRAGMENT_SIG_OIDS_END
   return(0);
}

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 */

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    OQSX_KEY *sig;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char *aid;
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    size_t mdsize;
    int operation;
} PROV_OQSSIG_CTX;


static size_t oqs_sig_get_md_size(const PROV_OQSSIG_CTX *poqs_sigctx)
{
    OQS_SIG_PRINTF("OQS SIG provider: get_md_size called\n");
    if (poqs_sigctx->md != NULL)
        return EVP_MD_size(poqs_sigctx->md);
    return 0;
}

static void *oqs_sig_newctx(void *provctx, const char *propq)
{
    PROV_OQSSIG_CTX *poqs_sigctx;

    OQS_SIG_PRINTF("OQS SIG provider: newctx called\n");

    poqs_sigctx = OPENSSL_zalloc(sizeof(PROV_OQSSIG_CTX));
    if (poqs_sigctx == NULL)
        return NULL;

    poqs_sigctx->libctx = ((PROV_OQS_CTX*)provctx)->libctx;
    poqs_sigctx->flag_allow_md = 0; // TBC
    if (propq != NULL && (poqs_sigctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(poqs_sigctx);
        poqs_sigctx = NULL;
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
    }
    return poqs_sigctx;
}

static int oqs_sig_setup_md(PROV_OQSSIG_CTX *ctx,
                        const char *mdname, const char *mdprops)
{
    OQS_SIG_PRINTF3("OQS SIG provider: setup_md called for MD %s (alg %s)\n", mdname, ctx->sig->key.s->method_name);
    if (mdprops == NULL)
        mdprops = ctx->propq;

    if (mdname != NULL) {
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);

        if (md == NULL) {
            if (md == NULL)
                ERR_raise_data(ERR_LIB_USER, OQSPROV_R_INVALID_DIGEST,
                               "%s could not be fetched", mdname);
            EVP_MD_free(md);
            return 0;
        }

        EVP_MD_CTX_free(ctx->mdctx);
        EVP_MD_free(ctx->md);

        OPENSSL_free(ctx->aid);
        ctx->aid = NULL; // ensure next function allocates memory
        ctx->aid_len = get_oqs_oid(ctx->aid, ctx->sig->key.s->method_name);

        ctx->mdctx = NULL;
        ctx->md = md;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    }
    return 1;
}

static int oqs_sig_signverify_init(void *vpoqs_sigctx, void *voqssig, int operation)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    OQS_SIG_PRINTF("OQS SIG provider: signverify_init called\n");
    if ( poqs_sigctx == NULL
            || voqssig == NULL
            || !oqsx_key_up_ref(voqssig))
        return 0;
    oqsx_key_free(poqs_sigctx->sig);
    poqs_sigctx->sig = voqssig;
    poqs_sigctx->operation = operation;
    if ( (operation==EVP_PKEY_OP_SIGN && !poqs_sigctx->sig->privkey) ||
         (operation==EVP_PKEY_OP_SIGN && !poqs_sigctx->sig->pubkey)) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
        return 0;
    }
    return 1;
}

static int oqs_sig_sign_init(void *vpoqs_sigctx, void *voqssig)
{
    OQS_SIG_PRINTF("OQS SIG provider: sign_init called\n");
    return oqs_sig_signverify_init(vpoqs_sigctx, voqssig, EVP_PKEY_OP_SIGN);
}

static int oqs_sig_verify_init(void *vpoqs_sigctx, void *voqssig)
{
    OQS_SIG_PRINTF("OQS SIG provider: verify_init called\n");
    return oqs_sig_signverify_init(vpoqs_sigctx, voqssig, EVP_PKEY_OP_VERIFY);
}

static int oqs_sig_sign(void *vpoqs_sigctx, unsigned char *sig, size_t *siglen,
                    size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    int ret = 0;
    size_t oqs_sigsize = poqs_sigctx->sig->key.s->length_signature;
    size_t mdsize = oqs_sig_get_md_size(poqs_sigctx);

    OQS_SIG_PRINTF("OQS SIG provider: sign called\n");

    if (sig == NULL) {
        *siglen = oqs_sigsize;
        return 1;
    }

    if (sigsize < (size_t)oqs_sigsize) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
        return 0;
    }

    if (mdsize != 0 && tbslen != mdsize) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
        return 0;
    }

    ret = OQS_SIG_sign(poqs_sigctx->sig->key.s, sig, siglen, tbs, tbslen, poqs_sigctx->sig->privkey);
    if (ret != OQS_SUCCESS) {
        printf("OQS sign error\n");
        return 0;
    }

    return 1;
}

static int oqs_sig_verify(void *vpoqs_sigctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    size_t mdsize = oqs_sig_get_md_size(poqs_sigctx);
    int ret = 0;

    OQS_SIG_PRINTF("OQS SIG provider: verify called\n");
    if (mdsize != 0 && tbslen != mdsize)
        return 0;

    ret = OQS_SIG_verify(poqs_sigctx->sig->key.s, tbs, tbslen, sig, siglen, poqs_sigctx->sig->pubkey);
    if (ret != OQS_SUCCESS) {
        printf("OQS sign error\n");
        return 0;
    }

    return 1;
}

static int oqs_sig_digest_signverify_init(void *vpoqs_sigctx, const char *mdname,
                                      void *voqssig, int operation)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    OQS_SIG_PRINTF("OQS SIG provider: digest_signverify called\n");

    poqs_sigctx->flag_allow_md = 0;
    if (!oqs_sig_signverify_init(vpoqs_sigctx, voqssig, operation))
        return 0;

    if (!oqs_sig_setup_md(poqs_sigctx, mdname, NULL))
        return 0;

    poqs_sigctx->mdctx = EVP_MD_CTX_new();
    if (poqs_sigctx->mdctx == NULL)
        goto error;

    if (!EVP_DigestInit_ex(poqs_sigctx->mdctx, poqs_sigctx->md, NULL))
        goto error;

    return 1;

 error:
    EVP_MD_CTX_free(poqs_sigctx->mdctx);
    EVP_MD_free(poqs_sigctx->md);
    poqs_sigctx->mdctx = NULL;
    poqs_sigctx->md = NULL;
    return 0;
}

static int oqs_sig_digest_sign_init(void *vpoqs_sigctx, const char *mdname,
                                      void *voqssig)
{
    OQS_SIG_PRINTF("OQS SIG provider: digest_sign_init called\n");
    return oqs_sig_digest_signverify_init(vpoqs_sigctx, mdname, voqssig, EVP_PKEY_OP_SIGN);
}

static int oqs_sig_digest_verify_init(void *vpoqs_sigctx, const char *mdname, void *voqssig)
{
    OQS_SIG_PRINTF("OQS SIG provider: sig_digest_verify called\n");
    return oqs_sig_digest_signverify_init(vpoqs_sigctx, mdname, voqssig, EVP_PKEY_OP_VERIFY);
}

int oqs_sig_digest_signverify_update(void *vpoqs_sigctx, const unsigned char *data,
                                 size_t datalen)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    OQS_SIG_PRINTF("OQS SIG provider: digest_signverify_update called\n");
    if (poqs_sigctx == NULL || poqs_sigctx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(poqs_sigctx->mdctx, data, datalen);
}

int oqs_sig_digest_sign_final(void *vpoqs_sigctx, unsigned char *sig, size_t *siglen,
                          size_t sigsize)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    OQS_SIG_PRINTF("OQS SIG provider: digest_sign_final called\n");
    if (poqs_sigctx == NULL || poqs_sigctx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to oqs_sig_sign.
     */
    if (sig != NULL) {
        /*
         * TODO(3.0): There is the possibility that some externally provided
         * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
         * but that problem is much larger than just here.
         */
        if (!EVP_DigestFinal_ex(poqs_sigctx->mdctx, digest, &dlen))
            return 0;
    }

    poqs_sigctx->flag_allow_md = 1;

    return oqs_sig_sign(vpoqs_sigctx, sig, siglen, sigsize, digest, (size_t)dlen);
}


int oqs_sig_digest_verify_final(void *vpoqs_sigctx, const unsigned char *sig,
                            size_t siglen)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    OQS_SIG_PRINTF("OQS SIG provider: digest_verify_final called\n");
    if (poqs_sigctx == NULL || poqs_sigctx->mdctx == NULL)
        return 0;

    /*
     * TODO(3.0): There is the possibility that some externally provided
     * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
     * but that problem is much larger than just here. 
     */
    if (!EVP_DigestFinal_ex(poqs_sigctx->mdctx, digest, &dlen))
        return 0;

    poqs_sigctx->flag_allow_md = 1;

    return oqs_sig_verify(vpoqs_sigctx, sig, siglen, digest, (size_t)dlen);
}

static void oqs_sig_freectx(void *vpoqs_sigctx)
{
    PROV_OQSSIG_CTX *ctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    OQS_SIG_PRINTF("OQS SIG provider: freectx called\n");
    OPENSSL_free(ctx->propq);
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->propq = NULL;
    ctx->mdctx = NULL;
    ctx->md = NULL;
    ctx->mdsize = 0;
    oqsx_key_free(ctx->sig);
    OPENSSL_free(ctx);
}

static void *oqs_sig_dupctx(void *vpoqs_sigctx)
{
    PROV_OQSSIG_CTX *srcctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    PROV_OQSSIG_CTX *dstctx;

    OQS_SIG_PRINTF("OQS SIG provider: dupctx called\n");

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->sig = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;

    if (srcctx->sig != NULL && !oqsx_key_up_ref(srcctx->sig))
        goto err;
    dstctx->sig = srcctx->sig;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }

    return dstctx;
 err:
    oqs_sig_freectx(dstctx);
    return NULL;
}

static int oqs_sig_get_ctx_params(void *vpoqs_sigctx, OSSL_PARAM *params)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    OSSL_PARAM *p;

    OQS_SIG_PRINTF("OQS SIG provider: get_ctx_params called\n");
    if (poqs_sigctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, poqs_sigctx->aid, poqs_sigctx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, poqs_sigctx->mdname))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *oqs_sig_gettable_ctx_params(ossl_unused void *vctx)
{
    OQS_SIG_PRINTF("OQS SIG provider: gettable_ctx_params called\n");
    return known_gettable_ctx_params;
}

static int oqs_sig_set_ctx_params(void *vpoqs_sigctx, const OSSL_PARAM params[])
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    const OSSL_PARAM *p;

    OQS_SIG_PRINTF("OQS SIG provider: set_ctx_params called\n");
    if (poqs_sigctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    /* Not allowed during certain operations */
    if (p != NULL && !poqs_sigctx->flag_allow_md)
        return 0;
    if (p != NULL) {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL
            && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;
        if (!oqs_sig_setup_md(poqs_sigctx, mdname, mdprops))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *oqs_sig_settable_ctx_params(ossl_unused void *provctx)
{
    /*
     * TODO(3.0): Should this function return a different set of settable ctx
     * params if the ctx is being used for a DigestSign/DigestVerify? In that
     * case it is not allowed to set the digest size/digest name because the
     * digest is explicitly set as part of the init.
     * NOTE: Ideally we would check poqs_sigctx->flag_allow_md, but this is
     * problematic because there is no nice way of passing the
     * PROV_OQSSIG_CTX down to this function...
     * Because we have API's that dont know about their parent..
     * e.g: EVP_SIGNATURE_gettable_ctx_params(const EVP_SIGNATURE *sig).
     * We could pass NULL for that case (but then how useful is the check?).
     */
    OQS_SIG_PRINTF("OQS SIG provider: settable_ctx_params called\n");
    return known_settable_ctx_params;
}

static int oqs_sig_get_ctx_md_params(void *vpoqs_sigctx, OSSL_PARAM *params)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    OQS_SIG_PRINTF("OQS SIG provider: get_ctx_md_params called\n");
    if (poqs_sigctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(poqs_sigctx->mdctx, params);
}

static const OSSL_PARAM *oqs_sig_gettable_ctx_md_params(void *vpoqs_sigctx)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    OQS_SIG_PRINTF("OQS SIG provider: gettable_ctx_md_params called\n");
    if (poqs_sigctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(poqs_sigctx->md);
}

static int oqs_sig_set_ctx_md_params(void *vpoqs_sigctx, const OSSL_PARAM params[])
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    OQS_SIG_PRINTF("OQS SIG provider: set_ctx_md_params called\n");
    if (poqs_sigctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(poqs_sigctx->mdctx, params);
}

static const OSSL_PARAM *oqs_sig_settable_ctx_md_params(void *vpoqs_sigctx)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    if (poqs_sigctx->md == NULL)
        return 0;

    OQS_SIG_PRINTF("OQS SIG provider: settable_ctx_md_params called\n");
    return EVP_MD_settable_ctx_params(poqs_sigctx->md);
}

// TBD: Templatize for #ALG where/if necessary
const OSSL_DISPATCH oqs_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))oqs_sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))oqs_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))oqs_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))oqs_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))oqs_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))oqs_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))oqs_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))oqs_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))oqs_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))oqs_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))oqs_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))oqs_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))oqs_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))oqs_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))oqs_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))oqs_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))oqs_sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))oqs_sig_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))oqs_sig_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))oqs_sig_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))oqs_sig_settable_ctx_md_params },
    { 0, NULL }
};
