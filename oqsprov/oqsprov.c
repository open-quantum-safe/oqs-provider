/* 
 * OQS OpenSSL 3 provider
 * 
 * Code strongly inspired by OpenSSL legacy provider.
 *
 * TBC: License banner
 *
 * ToDo: sigs.
 */

/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "prov/oqsx.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn oqsprovider_gettable_params;
static OSSL_FUNC_provider_get_params_fn oqsprovider_get_params;
static OSSL_FUNC_provider_query_operation_fn oqsprovider_query;
extern OSSL_FUNC_provider_get_capabilities_fn oqs_provider_get_capabilities;

#define ALG(NAMES, FUNC) { NAMES, "provider=oqsprovider", FUNC }

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM oqsprovider_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

extern const OSSL_DISPATCH oqs_generic_kem_functions[];
extern const OSSL_DISPATCH oqs_signature_functions[];

///// OQS_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_START
extern const OSSL_DISPATCH oqs_oqs_sig_default_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium4_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_falcon512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_falcon1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_picnicl1full_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_picnic3l1_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_rainbowIclassic_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_rainbowVclassic_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sphincsharaka128frobust_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sphincssha256128frobust_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sphincsshake256128frobust_keymgmt_functions[];

extern const OSSL_DISPATCH oqs_frodo640aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo640shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo976aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo976shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo1344aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo1344shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_bike1l1cpa_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_bike1l3cpa_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hps2048509_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hps2048677_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hps4096821_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hrss701_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_lightsaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_saber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_firesaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_bike1l1fo_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_bike1l3fo_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber90s512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber90s768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber90s1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_hqc128_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_hqc192_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_hqc256_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntrulpr653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntrulpr761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntrulpr857_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sntrup653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sntrup761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sntrup857_keymgmt_functions[];
///// OQS_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_END

static const OSSL_ALGORITHM oqsprovider_signatures[] = {
///// OQS_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_START
    ALG("oqs_sig_default", oqs_signature_functions),
    ALG("dilithium2", oqs_signature_functions),
    ALG("dilithium3", oqs_signature_functions),
    ALG("dilithium4", oqs_signature_functions),
    ALG("falcon512", oqs_signature_functions),
    ALG("falcon1024", oqs_signature_functions),
    ALG("picnicl1full", oqs_signature_functions),
    ALG("picnic3l1", oqs_signature_functions),
    ALG("rainbowIclassic", oqs_signature_functions),
    ALG("rainbowVclassic", oqs_signature_functions),
    ALG("sphincsharaka128frobust", oqs_signature_functions),
    ALG("sphincssha256128frobust", oqs_signature_functions),
    ALG("sphincsshake256128frobust", oqs_signature_functions),
///// OQS_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_END
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM oqsprovider_asym_kems[] = {
///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_START
    ALG("frodo640aes", oqs_generic_kem_functions),
    ALG("frodo640shake", oqs_generic_kem_functions),
    ALG("frodo976aes", oqs_generic_kem_functions),
    ALG("frodo976shake", oqs_generic_kem_functions),
    ALG("frodo1344aes", oqs_generic_kem_functions),
    ALG("frodo1344shake", oqs_generic_kem_functions),
    ALG("bike1l1cpa", oqs_generic_kem_functions),
    ALG("bike1l3cpa", oqs_generic_kem_functions),
    ALG("kyber512", oqs_generic_kem_functions),
    ALG("kyber768", oqs_generic_kem_functions),
    ALG("kyber1024", oqs_generic_kem_functions),
    ALG("ntru_hps2048509", oqs_generic_kem_functions),
    ALG("ntru_hps2048677", oqs_generic_kem_functions),
    ALG("ntru_hps4096821", oqs_generic_kem_functions),
    ALG("ntru_hrss701", oqs_generic_kem_functions),
    ALG("lightsaber", oqs_generic_kem_functions),
    ALG("saber", oqs_generic_kem_functions),
    ALG("firesaber", oqs_generic_kem_functions),
    ALG("sidhp434", oqs_generic_kem_functions),
    ALG("sidhp503", oqs_generic_kem_functions),
    ALG("sidhp610", oqs_generic_kem_functions),
    ALG("sidhp751", oqs_generic_kem_functions),
    ALG("sikep434", oqs_generic_kem_functions),
    ALG("sikep503", oqs_generic_kem_functions),
    ALG("sikep610", oqs_generic_kem_functions),
    ALG("sikep751", oqs_generic_kem_functions),
    ALG("bike1l1fo", oqs_generic_kem_functions),
    ALG("bike1l3fo", oqs_generic_kem_functions),
    ALG("kyber90s512", oqs_generic_kem_functions),
    ALG("kyber90s768", oqs_generic_kem_functions),
    ALG("kyber90s1024", oqs_generic_kem_functions),
    ALG("hqc128", oqs_generic_kem_functions),
    ALG("hqc192", oqs_generic_kem_functions),
    ALG("hqc256", oqs_generic_kem_functions),
    ALG("ntrulpr653", oqs_generic_kem_functions),
    ALG("ntrulpr761", oqs_generic_kem_functions),
    ALG("ntrulpr857", oqs_generic_kem_functions),
    ALG("sntrup653", oqs_generic_kem_functions),
    ALG("sntrup761", oqs_generic_kem_functions),
    ALG("sntrup857", oqs_generic_kem_functions),
///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_END
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM oqsprovider_keymgmt[] = {
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
    ALG("oqs_sig_default", oqs_oqs_sig_default_keymgmt_functions),
    ALG("dilithium2", oqs_dilithium2_keymgmt_functions),
    ALG("dilithium3", oqs_dilithium3_keymgmt_functions),
    ALG("dilithium4", oqs_dilithium4_keymgmt_functions),
    ALG("falcon512", oqs_falcon512_keymgmt_functions),
    ALG("falcon1024", oqs_falcon1024_keymgmt_functions),
    ALG("picnicl1full", oqs_picnicl1full_keymgmt_functions),
    ALG("picnic3l1", oqs_picnic3l1_keymgmt_functions),
    ALG("rainbowIclassic", oqs_rainbowIclassic_keymgmt_functions),
    ALG("rainbowVclassic", oqs_rainbowVclassic_keymgmt_functions),
    ALG("sphincsharaka128frobust", oqs_sphincsharaka128frobust_keymgmt_functions),
    ALG("sphincssha256128frobust", oqs_sphincssha256128frobust_keymgmt_functions),
    ALG("sphincsshake256128frobust", oqs_sphincsshake256128frobust_keymgmt_functions),

    ALG("frodo640aes", oqs_frodo640aes_keymgmt_functions),
    ALG("frodo640shake", oqs_frodo640shake_keymgmt_functions),
    ALG("frodo976aes", oqs_frodo976aes_keymgmt_functions),
    ALG("frodo976shake", oqs_frodo976shake_keymgmt_functions),
    ALG("frodo1344aes", oqs_frodo1344aes_keymgmt_functions),
    ALG("frodo1344shake", oqs_frodo1344shake_keymgmt_functions),
    ALG("bike1l1cpa", oqs_bike1l1cpa_keymgmt_functions),
    ALG("bike1l3cpa", oqs_bike1l3cpa_keymgmt_functions),
    ALG("kyber512", oqs_kyber512_keymgmt_functions),
    ALG("kyber768", oqs_kyber768_keymgmt_functions),
    ALG("kyber1024", oqs_kyber1024_keymgmt_functions),
    ALG("ntru_hps2048509", oqs_ntru_hps2048509_keymgmt_functions),
    ALG("ntru_hps2048677", oqs_ntru_hps2048677_keymgmt_functions),
    ALG("ntru_hps4096821", oqs_ntru_hps4096821_keymgmt_functions),
    ALG("ntru_hrss701", oqs_ntru_hrss701_keymgmt_functions),
    ALG("lightsaber", oqs_lightsaber_keymgmt_functions),
    ALG("saber", oqs_saber_keymgmt_functions),
    ALG("firesaber", oqs_firesaber_keymgmt_functions),
    ALG("sidhp434", oqs_sidhp434_keymgmt_functions),
    ALG("sidhp503", oqs_sidhp503_keymgmt_functions),
    ALG("sidhp610", oqs_sidhp610_keymgmt_functions),
    ALG("sidhp751", oqs_sidhp751_keymgmt_functions),
    ALG("sikep434", oqs_sikep434_keymgmt_functions),
    ALG("sikep503", oqs_sikep503_keymgmt_functions),
    ALG("sikep610", oqs_sikep610_keymgmt_functions),
    ALG("sikep751", oqs_sikep751_keymgmt_functions),
    ALG("bike1l1fo", oqs_bike1l1fo_keymgmt_functions),
    ALG("bike1l3fo", oqs_bike1l3fo_keymgmt_functions),
    ALG("kyber90s512", oqs_kyber90s512_keymgmt_functions),
    ALG("kyber90s768", oqs_kyber90s768_keymgmt_functions),
    ALG("kyber90s1024", oqs_kyber90s1024_keymgmt_functions),
    ALG("hqc128", oqs_hqc128_keymgmt_functions),
    ALG("hqc192", oqs_hqc192_keymgmt_functions),
    ALG("hqc256", oqs_hqc256_keymgmt_functions),
    ALG("ntrulpr653", oqs_ntrulpr653_keymgmt_functions),
    ALG("ntrulpr761", oqs_ntrulpr761_keymgmt_functions),
    ALG("ntrulpr857", oqs_ntrulpr857_keymgmt_functions),
    ALG("sntrup653", oqs_sntrup653_keymgmt_functions),
    ALG("sntrup761", oqs_sntrup761_keymgmt_functions),
    ALG("sntrup857", oqs_sntrup857_keymgmt_functions),
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_END
    { NULL, NULL, NULL }
};

static const OSSL_PARAM *oqsprovider_gettable_params(void *provctx)
{
    return oqsprovider_param_types;
}

static int oqsprovider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL OQS Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) // provider is always running
        return 0;
    return 1;
}

static const OSSL_ALGORITHM *oqsprovider_query(void *provctx, int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return oqsprovider_signatures;
    case OSSL_OP_KEM:
        return oqsprovider_asym_kems;
    case OSSL_OP_KEYMGMT:
        return oqsprovider_keymgmt;
    default:
        if (getenv("OQSPROV")) printf("Unknown operation %d requested from OQS provider\n", operation_id);
    }
    return NULL;
}

static void oqsprovider_teardown(void *provctx)
{
   oqsx_freeprovctx((PROV_OQS_CTX*)provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH oqsprovider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))oqsprovider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))oqsprovider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))oqsprovider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))oqsprovider_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))oqs_provider_get_capabilities },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    OSSL_LIB_CTX *libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    if ( ((libctx = OSSL_LIB_CTX_new()) == NULL) ||
         (*provctx = oqsx_newprovctx(libctx, handle)) == NULL ) {
        OSSL_LIB_CTX_free(libctx);
        oqsprovider_teardown(*provctx);
        *provctx = NULL;
        return 0;
    }

    *out = oqsprovider_dispatch_table;

    return 1;
}
///// OQS_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_START
extern const OSSL_DISPATCH oqs_oqs_sig_default_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium4_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_falcon512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_falcon1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_picnicl1full_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_picnic3l1_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_rainbowIclassic_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_rainbowVclassic_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sphincsharaka128frobust_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sphincssha256128frobust_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sphincsshake256128frobust_keymgmt_functions[];

extern const OSSL_DISPATCH oqs_frodo640aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo640shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo976aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo976shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo1344aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo1344shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_bike1l1cpa_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_bike1l3cpa_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hps2048509_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hps2048677_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hps4096821_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hrss701_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_lightsaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_saber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_firesaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_bike1l1fo_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_bike1l3fo_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber90s512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber90s768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber90s1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_hqc128_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_hqc192_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_hqc256_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntrulpr653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntrulpr761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntrulpr857_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sntrup653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sntrup761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sntrup857_keymgmt_functions[];

