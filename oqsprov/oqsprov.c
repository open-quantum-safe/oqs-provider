// SPDX-License-Identifier: Apache-2.0 AND MIT

/* 
 * OQS OpenSSL 3 provider
 * 
 * Code strongly inspired by OpenSSL legacy provider.
 *
 * ToDo: encoder/decoders
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "oqsx.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn oqsprovider_gettable_params;
static OSSL_FUNC_provider_get_params_fn oqsprovider_get_params;
static OSSL_FUNC_provider_query_operation_fn oqsprovider_query;
extern OSSL_FUNC_provider_get_capabilities_fn oqs_provider_get_capabilities;

#define ALG(NAMES, FUNC) { NAMES, "provider=oqsprovider", FUNC }
#define KEMALG3(NAMES, SECBITS) \
    { "" #NAMES "", "provider=oqsprovider", oqs_generic_kem_functions }, \
    { ECP_NAME(SECBITS, NAMES), "provider=oqsprovider", oqs_hybrid_kem_functions }, \
    { ECX_NAME(SECBITS, NAMES), "provider=oqsprovider", oqs_hybrid_kem_functions }
#define KEMKMALG3(NAMES, SECBITS) \
    { "" #NAMES "", "provider=oqsprovider", oqs_##NAMES##_keymgmt_functions }, \
    { ECP_NAME(SECBITS, NAMES), "provider=oqsprovider", oqs_ecp_##NAMES##_keymgmt_functions }, \
    { ECX_NAME(SECBITS, NAMES), "provider=oqsprovider", oqs_ecx_##NAMES##_keymgmt_functions }

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
extern const OSSL_DISPATCH oqs_hybrid_kem_functions[];
extern const OSSL_DISPATCH oqs_signature_functions[];

///// OQS_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_START
extern const OSSL_DISPATCH oqs_oqs_sig_default_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_aes_keymgmt_functions[];
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

extern const OSSL_DISPATCH oqs_ecp_frodo640aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_frodo640shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_frodo976aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_frodo976shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_frodo1344aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_frodo1344shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_bike1l1cpa_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_bike1l3cpa_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntru_hps2048509_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntru_hps2048677_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntru_hps4096821_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntru_hrss701_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_lightsaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_saber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_firesaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sidhp434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sidhp503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sidhp610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sidhp751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sikep434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sikep503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sikep610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sikep751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_bike1l1fo_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_bike1l3fo_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber90s512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber90s768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber90s1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_hqc128_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_hqc192_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_hqc256_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntrulpr653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntrulpr761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntrulpr857_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sntrup653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sntrup761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sntrup857_keymgmt_functions[];

extern const OSSL_DISPATCH oqs_ecx_frodo640aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_frodo640shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_frodo976aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_frodo976shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_frodo1344aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_frodo1344shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_bike1l1cpa_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_bike1l3cpa_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntru_hps2048509_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntru_hps2048677_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntru_hps4096821_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntru_hrss701_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_lightsaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_saber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_firesaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sidhp434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sidhp503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sidhp610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sidhp751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sikep434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sikep503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sikep610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sikep751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_bike1l1fo_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_bike1l3fo_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber90s512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber90s768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber90s1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_hqc128_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_hqc192_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_hqc256_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntrulpr653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntrulpr761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntrulpr857_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sntrup653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sntrup761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sntrup857_keymgmt_functions[];
///// OQS_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_END

static const OSSL_ALGORITHM oqsprovider_signatures[] = {
///// OQS_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_START
    ALG("oqs_sig_default", oqs_signature_functions),
    ALG("dilithium2", oqs_signature_functions),
    ALG("dilithium3", oqs_signature_functions),
    ALG("dilithium5", oqs_signature_functions),
    ALG("dilithium2_aes", oqs_signature_functions),
    ALG("dilithium3_aes", oqs_signature_functions),
    ALG("dilithium5_aes", oqs_signature_functions),
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
    KEMALG3(frodo640aes, 128),
    KEMALG3(frodo640shake, 128),
    KEMALG3(frodo976aes, 192),
    KEMALG3(frodo976shake, 192),
    KEMALG3(frodo1344aes, 256),
    KEMALG3(frodo1344shake, 256),
    KEMALG3(bike1l1cpa, 128),
    KEMALG3(bike1l3cpa, 192),
    KEMALG3(kyber512, 128),
    KEMALG3(kyber768, 192),
    KEMALG3(kyber1024, 256),
    KEMALG3(ntru_hps2048509, 128),
    KEMALG3(ntru_hps2048677, 192),
    KEMALG3(ntru_hps4096821, 256),
    KEMALG3(ntru_hrss701, 192),
    KEMALG3(lightsaber, 128),
    KEMALG3(saber, 192),
    KEMALG3(firesaber, 256),
    KEMALG3(sidhp434, 128),
    KEMALG3(sidhp503, 128),
    KEMALG3(sidhp610, 192),
    KEMALG3(sidhp751, 256),
    KEMALG3(sikep434, 128),
    KEMALG3(sikep503, 128),
    KEMALG3(sikep610, 192),
    KEMALG3(sikep751, 256),
    KEMALG3(bike1l1fo, 128),
    KEMALG3(bike1l3fo, 192),
    KEMALG3(kyber90s512, 128),
    KEMALG3(kyber90s768, 192),
    KEMALG3(kyber90s1024, 256),
    KEMALG3(hqc128, 128),
    KEMALG3(hqc192, 192),
    KEMALG3(hqc256, 256),
    KEMALG3(ntrulpr653, 128),
    KEMALG3(ntrulpr761, 192),
    KEMALG3(ntrulpr857, 192),
    KEMALG3(sntrup653, 128),
    KEMALG3(sntrup761, 192),
    KEMALG3(sntrup857, 192),
///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_END
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM oqsprovider_keymgmt[] = {
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
    ALG("oqs_sig_default", oqs_oqs_sig_default_keymgmt_functions),
    ALG("dilithium2", oqs_dilithium2_keymgmt_functions),
    ALG("dilithium3", oqs_dilithium3_keymgmt_functions),
    ALG("dilithium5", oqs_dilithium5_keymgmt_functions),
    ALG("dilithium2_aes", oqs_dilithium2_aes_keymgmt_functions),
    ALG("dilithium3_aes", oqs_dilithium3_aes_keymgmt_functions),
    ALG("dilithium5_aes", oqs_dilithium5_aes_keymgmt_functions),
    ALG("falcon512", oqs_falcon512_keymgmt_functions),
    ALG("falcon1024", oqs_falcon1024_keymgmt_functions),
    ALG("picnicl1full", oqs_picnicl1full_keymgmt_functions),
    ALG("picnic3l1", oqs_picnic3l1_keymgmt_functions),
    ALG("rainbowIclassic", oqs_rainbowIclassic_keymgmt_functions),
    ALG("rainbowVclassic", oqs_rainbowVclassic_keymgmt_functions),
    ALG("sphincsharaka128frobust", oqs_sphincsharaka128frobust_keymgmt_functions),
    ALG("sphincssha256128frobust", oqs_sphincssha256128frobust_keymgmt_functions),
    ALG("sphincsshake256128frobust", oqs_sphincsshake256128frobust_keymgmt_functions),

    KEMKMALG3(frodo640aes, 128),
    KEMKMALG3(frodo640shake, 128),
    KEMKMALG3(frodo976aes, 192),
    KEMKMALG3(frodo976shake, 192),
    KEMKMALG3(frodo1344aes, 256),
    KEMKMALG3(frodo1344shake, 256),
    KEMKMALG3(bike1l1cpa, 128),
    KEMKMALG3(bike1l3cpa, 192),
    KEMKMALG3(kyber512, 128),
    KEMKMALG3(kyber768, 192),
    KEMKMALG3(kyber1024, 256),
    KEMKMALG3(ntru_hps2048509, 128),
    KEMKMALG3(ntru_hps2048677, 192),
    KEMKMALG3(ntru_hps4096821, 256),
    KEMKMALG3(ntru_hrss701, 192),
    KEMKMALG3(lightsaber, 128),
    KEMKMALG3(saber, 192),
    KEMKMALG3(firesaber, 256),
    KEMKMALG3(sidhp434, 128),
    KEMKMALG3(sidhp503, 128),
    KEMKMALG3(sidhp610, 192),
    KEMKMALG3(sidhp751, 256),
    KEMKMALG3(sikep434, 128),
    KEMKMALG3(sikep503, 128),
    KEMKMALG3(sikep610, 192),
    KEMKMALG3(sikep751, 256),
    KEMKMALG3(bike1l1fo, 128),
    KEMKMALG3(bike1l3fo, 192),
    KEMKMALG3(kyber90s512, 128),
    KEMKMALG3(kyber90s768, 192),
    KEMKMALG3(kyber90s1024, 256),
    KEMKMALG3(hqc128, 128),
    KEMKMALG3(hqc192, 192),
    KEMKMALG3(hqc256, 256),
    KEMKMALG3(ntrulpr653, 128),
    KEMKMALG3(ntrulpr761, 192),
    KEMKMALG3(ntrulpr857, 192),
    KEMKMALG3(sntrup653, 128),
    KEMKMALG3(sntrup761, 192),
    KEMKMALG3(sntrup857, 192),
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_END
    //ALG("x25519_sikep434", oqs_ecx_sikep434_keymgmt_functions),
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
