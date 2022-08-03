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
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include "oqs_prov.h"

#ifdef NDEBUG
#define OQS_PROV_PRINTF(a)
#define OQS_PROV_PRINTF2(a, b)
#define OQS_PROV_PRINTF3(a, b, c)
#else
#define OQS_PROV_PRINTF(a) if (getenv("OQSPROV")) printf(a)
#define OQS_PROV_PRINTF2(a, b) if (getenv("OQSPROV")) printf(a, b)
#define OQS_PROV_PRINTF3(a, b, c) if (getenv("OQSPROV")) printf(a, b, c)
#endif // NDEBUG

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn oqsprovider_gettable_params;
static OSSL_FUNC_provider_get_params_fn oqsprovider_get_params;
static OSSL_FUNC_provider_query_operation_fn oqsprovider_query;
extern OSSL_FUNC_provider_get_capabilities_fn oqs_provider_get_capabilities;

/* 
 * List of all algorithms with given OIDs
 */
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_START
#define OQS_OID_CNT 72
static const char* oqs_oid_alg_list[OQS_OID_CNT] =
{
"1.3.6.1.4.1.2.267.7.4.4", "dilithium2",
"1.3.9999.2.7.1" , "p256_dilithium2",
"1.3.9999.2.7.2" , "rsa3072_dilithium2",
"1.3.6.1.4.1.2.267.7.6.5", "dilithium3",
"1.3.9999.2.7.3" , "p384_dilithium3",
"1.3.6.1.4.1.2.267.7.8.7", "dilithium5",
"1.3.9999.2.7.4" , "p521_dilithium5",
"1.3.6.1.4.1.2.267.11.4.4", "dilithium2_aes",
"1.3.9999.2.11.1" , "p256_dilithium2_aes",
"1.3.9999.2.11.2" , "rsa3072_dilithium2_aes",
"1.3.6.1.4.1.2.267.11.6.5", "dilithium3_aes",
"1.3.9999.2.11.3" , "p384_dilithium3_aes",
"1.3.6.1.4.1.2.267.11.8.7", "dilithium5_aes",
"1.3.9999.2.11.4" , "p521_dilithium5_aes",
"1.3.9999.3.1", "falcon512",
"1.3.9999.3.2" , "p256_falcon512",
"1.3.9999.3.3" , "rsa3072_falcon512",
"1.3.9999.3.4", "falcon1024",
"1.3.9999.3.5" , "p521_falcon1024",
"1.3.6.1.4.1.311.89.2.1.7", "picnicl1full",
"1.3.6.1.4.1.311.89.2.1.8" , "p256_picnicl1full",
"1.3.6.1.4.1.311.89.2.1.9" , "rsa3072_picnicl1full",
"1.3.6.1.4.1.311.89.2.1.21", "picnic3l1",
"1.3.6.1.4.1.311.89.2.1.22" , "p256_picnic3l1",
"1.3.6.1.4.1.311.89.2.1.23" , "rsa3072_picnic3l1",
"1.3.9999.5.3.1.1", "rainbowVclassic",
"1.3.9999.5.3.2.1" , "p521_rainbowVclassic",
"1.3.9999.6.1.1", "sphincsharaka128frobust",
"1.3.9999.6.1.2" , "p256_sphincsharaka128frobust",
"1.3.9999.6.1.3" , "rsa3072_sphincsharaka128frobust",
"1.3.9999.6.4.1", "sphincssha256128frobust",
"1.3.9999.6.4.2" , "p256_sphincssha256128frobust",
"1.3.9999.6.4.3" , "rsa3072_sphincssha256128frobust",
"1.3.9999.6.7.1", "sphincsshake256128frobust",
"1.3.9999.6.7.2" , "p256_sphincsshake256128frobust",
"1.3.9999.6.7.3" , "rsa3072_sphincsshake256128frobust",
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_END
};

#define ALG(NAMES, FUNC) { NAMES, "provider=oqsprovider", FUNC }
#define KEMALG3(NAMES, SECBITS) \
    { "" #NAMES "", "provider=oqsprovider", oqs_generic_kem_functions }, \
    { ECP_NAME(SECBITS, NAMES), "provider=oqsprovider", oqs_hybrid_kem_functions }, \
    { ECX_NAME(SECBITS, NAMES), "provider=oqsprovider", oqs_hybrid_kem_functions }
#define KEMKMALG3(NAMES, SECBITS) \
    { "" #NAMES "", "provider=oqsprovider", oqs_##NAMES##_keymgmt_functions }, \
    { ECP_NAME(SECBITS, NAMES), "provider=oqsprovider", oqs_ecp_##NAMES##_keymgmt_functions }, \
    { ECX_NAME(SECBITS, NAMES), "provider=oqsprovider", oqs_ecx_##NAMES##_keymgmt_functions }
#define KEMALG2(NAMES, SECBITS) \
    { "" #NAMES "", "provider=oqsprovider", oqs_generic_kem_functions }, \
    { ECP_NAME(SECBITS, NAMES), "provider=oqsprovider", oqs_hybrid_kem_functions }
#define KEMKMALG2(NAMES, SECBITS) \
    { "" #NAMES "", "provider=oqsprovider", oqs_##NAMES##_keymgmt_functions }, \
    { ECP_NAME(SECBITS, NAMES), "provider=oqsprovider", oqs_ecp_##NAMES##_keymgmt_functions }

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


static const OSSL_ALGORITHM oqsprovider_signatures[] = {
///// OQS_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_START
    ALG("dilithium2", oqs_signature_functions),
    ALG("p256_dilithium2", oqs_signature_functions),
    ALG("rsa3072_dilithium2", oqs_signature_functions),
    ALG("dilithium3", oqs_signature_functions),
    ALG("p384_dilithium3", oqs_signature_functions),
    ALG("dilithium5", oqs_signature_functions),
    ALG("p521_dilithium5", oqs_signature_functions),
    ALG("dilithium2_aes", oqs_signature_functions),
    ALG("p256_dilithium2_aes", oqs_signature_functions),
    ALG("rsa3072_dilithium2_aes", oqs_signature_functions),
    ALG("dilithium3_aes", oqs_signature_functions),
    ALG("p384_dilithium3_aes", oqs_signature_functions),
    ALG("dilithium5_aes", oqs_signature_functions),
    ALG("p521_dilithium5_aes", oqs_signature_functions),
    ALG("falcon512", oqs_signature_functions),
    ALG("p256_falcon512", oqs_signature_functions),
    ALG("rsa3072_falcon512", oqs_signature_functions),
    ALG("falcon1024", oqs_signature_functions),
    ALG("p521_falcon1024", oqs_signature_functions),
    ALG("picnicl1full", oqs_signature_functions),
    ALG("p256_picnicl1full", oqs_signature_functions),
    ALG("rsa3072_picnicl1full", oqs_signature_functions),
    ALG("picnic3l1", oqs_signature_functions),
    ALG("p256_picnic3l1", oqs_signature_functions),
    ALG("rsa3072_picnic3l1", oqs_signature_functions),
    ALG("rainbowVclassic", oqs_signature_functions),
    ALG("p521_rainbowVclassic", oqs_signature_functions),
    ALG("sphincsharaka128frobust", oqs_signature_functions),
    ALG("p256_sphincsharaka128frobust", oqs_signature_functions),
    ALG("rsa3072_sphincsharaka128frobust", oqs_signature_functions),
    ALG("sphincssha256128frobust", oqs_signature_functions),
    ALG("p256_sphincssha256128frobust", oqs_signature_functions),
    ALG("rsa3072_sphincssha256128frobust", oqs_signature_functions),
    ALG("sphincsshake256128frobust", oqs_signature_functions),
    ALG("p256_sphincsshake256128frobust", oqs_signature_functions),
    ALG("rsa3072_sphincsshake256128frobust", oqs_signature_functions),
///// OQS_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_END
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM oqsprovider_asym_kems[] = {
///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_START
    KEMALG3(frodo640aes, 128),
    KEMALG3(frodo640shake, 128),
    KEMALG3(frodo976aes, 192),
    KEMALG3(frodo976shake, 192),
    KEMALG2(frodo1344aes, 256),
    KEMALG2(frodo1344shake, 256),
    KEMALG3(kyber512, 128),
    KEMALG3(kyber768, 192),
    KEMALG2(kyber1024, 256),
    KEMALG3(ntru_hps2048509, 128),
    KEMALG3(ntru_hps2048677, 192),
    KEMALG2(ntru_hps4096821, 256),
    KEMALG2(ntru_hps40961229, 256),
    KEMALG3(ntru_hrss701, 192),
    KEMALG2(ntru_hrss1373, 256),
    KEMALG3(lightsaber, 128),
    KEMALG3(saber, 192),
    KEMALG2(firesaber, 256),
    KEMALG3(bikel1, 128),
    KEMALG3(bikel3, 192),
    KEMALG3(kyber90s512, 128),
    KEMALG3(kyber90s768, 192),
    KEMALG2(kyber90s1024, 256),
    KEMALG3(hqc128, 128),
    KEMALG3(hqc192, 192),
    KEMALG2(hqc256, 256),
    KEMALG3(ntrulpr653, 128),
    KEMALG3(ntrulpr761, 128),
    KEMALG3(ntrulpr857, 192),
    KEMALG2(ntrulpr1277, 256),
    KEMALG3(sntrup653, 128),
    KEMALG3(sntrup761, 128),
    KEMALG3(sntrup857, 192),
    KEMALG2(sntrup1277, 256),
///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_END
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM oqsprovider_keymgmt[] = {
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
    ALG("dilithium2", oqs_dilithium2_keymgmt_functions),ALG("p256_dilithium2", oqs_p256_dilithium2_keymgmt_functions),ALG("rsa3072_dilithium2", oqs_rsa3072_dilithium2_keymgmt_functions),
    ALG("dilithium3", oqs_dilithium3_keymgmt_functions),ALG("p384_dilithium3", oqs_p384_dilithium3_keymgmt_functions),
    ALG("dilithium5", oqs_dilithium5_keymgmt_functions),ALG("p521_dilithium5", oqs_p521_dilithium5_keymgmt_functions),
    ALG("dilithium2_aes", oqs_dilithium2_aes_keymgmt_functions),ALG("p256_dilithium2_aes", oqs_p256_dilithium2_aes_keymgmt_functions),ALG("rsa3072_dilithium2_aes", oqs_rsa3072_dilithium2_aes_keymgmt_functions),
    ALG("dilithium3_aes", oqs_dilithium3_aes_keymgmt_functions),ALG("p384_dilithium3_aes", oqs_p384_dilithium3_aes_keymgmt_functions),
    ALG("dilithium5_aes", oqs_dilithium5_aes_keymgmt_functions),ALG("p521_dilithium5_aes", oqs_p521_dilithium5_aes_keymgmt_functions),
    ALG("falcon512", oqs_falcon512_keymgmt_functions),ALG("p256_falcon512", oqs_p256_falcon512_keymgmt_functions),ALG("rsa3072_falcon512", oqs_rsa3072_falcon512_keymgmt_functions),
    ALG("falcon1024", oqs_falcon1024_keymgmt_functions),ALG("p521_falcon1024", oqs_p521_falcon1024_keymgmt_functions),
    ALG("picnicl1full", oqs_picnicl1full_keymgmt_functions),ALG("p256_picnicl1full", oqs_p256_picnicl1full_keymgmt_functions),ALG("rsa3072_picnicl1full", oqs_rsa3072_picnicl1full_keymgmt_functions),
    ALG("picnic3l1", oqs_picnic3l1_keymgmt_functions),ALG("p256_picnic3l1", oqs_p256_picnic3l1_keymgmt_functions),ALG("rsa3072_picnic3l1", oqs_rsa3072_picnic3l1_keymgmt_functions),
    ALG("rainbowVclassic", oqs_rainbowVclassic_keymgmt_functions),ALG("p521_rainbowVclassic", oqs_p521_rainbowVclassic_keymgmt_functions),
    ALG("sphincsharaka128frobust", oqs_sphincsharaka128frobust_keymgmt_functions),ALG("p256_sphincsharaka128frobust", oqs_p256_sphincsharaka128frobust_keymgmt_functions),ALG("rsa3072_sphincsharaka128frobust", oqs_rsa3072_sphincsharaka128frobust_keymgmt_functions),
    ALG("sphincssha256128frobust", oqs_sphincssha256128frobust_keymgmt_functions),ALG("p256_sphincssha256128frobust", oqs_p256_sphincssha256128frobust_keymgmt_functions),ALG("rsa3072_sphincssha256128frobust", oqs_rsa3072_sphincssha256128frobust_keymgmt_functions),
    ALG("sphincsshake256128frobust", oqs_sphincsshake256128frobust_keymgmt_functions),ALG("p256_sphincsshake256128frobust", oqs_p256_sphincsshake256128frobust_keymgmt_functions),ALG("rsa3072_sphincsshake256128frobust", oqs_rsa3072_sphincsshake256128frobust_keymgmt_functions),

    KEMKMALG3(frodo640aes, 128),
    KEMKMALG3(frodo640shake, 128),
    KEMKMALG3(frodo976aes, 192),
    KEMKMALG3(frodo976shake, 192),
    KEMKMALG2(frodo1344aes, 256),
    KEMKMALG2(frodo1344shake, 256),
    KEMKMALG3(kyber512, 128),
    KEMKMALG3(kyber768, 192),
    KEMKMALG2(kyber1024, 256),
    KEMKMALG3(ntru_hps2048509, 128),
    KEMKMALG3(ntru_hps2048677, 192),
    KEMKMALG2(ntru_hps4096821, 256),
    KEMKMALG2(ntru_hps40961229, 256),
    KEMKMALG3(ntru_hrss701, 192),
    KEMKMALG2(ntru_hrss1373, 256),
    KEMKMALG3(lightsaber, 128),
    KEMKMALG3(saber, 192),
    KEMKMALG2(firesaber, 256),
    KEMKMALG3(bikel1, 128),
    KEMKMALG3(bikel3, 192),
    KEMKMALG3(kyber90s512, 128),
    KEMKMALG3(kyber90s768, 192),
    KEMKMALG2(kyber90s1024, 256),
    KEMKMALG3(hqc128, 128),
    KEMKMALG3(hqc192, 192),
    KEMKMALG2(hqc256, 256),
    KEMKMALG3(ntrulpr653, 128),
    KEMKMALG3(ntrulpr761, 128),
    KEMKMALG3(ntrulpr857, 192),
    KEMKMALG2(ntrulpr1277, 256),
    KEMKMALG3(sntrup653, 128),
    KEMKMALG3(sntrup761, 128),
    KEMKMALG3(sntrup857, 192),
    KEMKMALG2(sntrup1277, 256),
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_END
    //ALG("x25519_sikep434", oqs_ecx_sikep434_keymgmt_functions),
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM oqsprovider_encoder[] = {
#define ENCODER_PROVIDER "oqsprovider"
#include "oqsencoders.inc"
    { NULL, NULL, NULL }
#undef ENCODER_PROVIDER
};

static const OSSL_ALGORITHM oqsprovider_decoder[] = {
#define DECODER_PROVIDER "oqsprovider"
#include "oqsdecoders.inc"
    { NULL, NULL, NULL }
#undef DECODER_PROVIDER
};


static const OSSL_PARAM *oqsprovider_gettable_params(void *provctx)
{
    return oqsprovider_param_types;
}

#define OQS_PROVIDER_BUILD_INFO_STR "OQS Provider v." OQS_PROVIDER_VERSION_STR " based on liboqs v." OQS_VERSION_TEXT

static int oqsprovider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL OQS Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OQS_PROVIDER_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OQS_PROVIDER_BUILD_INFO_STR))
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
    case OSSL_OP_ENCODER:
        return oqsprovider_encoder;
    case OSSL_OP_DECODER:
        return oqsprovider_decoder;
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
    const OSSL_DISPATCH *orig_in=in;
    OSSL_FUNC_core_obj_create_fn *c_obj_create= NULL;

    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid= NULL;
    BIO_METHOD *corebiometh;
    OSSL_LIB_CTX *libctx = NULL;
    int i, rc = 0;

    if (!oqs_prov_bio_from_dispatch(in))
        return 0;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_OBJ_CREATE:
            c_obj_create = OSSL_FUNC_core_obj_create(in);
            break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    // we need these functions:
    if (c_obj_create == NULL || c_obj_add_sigid==NULL)
        return 0;

    // insert all OIDs to the global objects list
    for (i=0; i<OQS_OID_CNT;i+=2) {
	if (!c_obj_create(handle, oqs_oid_alg_list[i], oqs_oid_alg_list[i+1], oqs_oid_alg_list[i+1]))
                ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);

	if (!oqs_set_nid((char*)oqs_oid_alg_list[i+1], OBJ_sn2nid(oqs_oid_alg_list[i+1])))
              ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);

	if (!c_obj_add_sigid(handle, oqs_oid_alg_list[i+1], "", oqs_oid_alg_list[i+1])) {
              OQS_PROV_PRINTF2("error registering %s with no hash\n", oqs_oid_alg_list[i+1]);
              ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
	}

        OQS_PROV_PRINTF3("OQS PROV: successfully registered %s with NID %d\n", oqs_oid_alg_list[i+1], OBJ_sn2nid(oqs_oid_alg_list[i+1]));

    }

    // if libctx not yet existing, create a new one
    if ( ((corebiometh = oqs_bio_prov_init_bio_method()) == NULL) ||
         ((libctx = OSSL_LIB_CTX_new_child(handle, orig_in)) == NULL) ||
         ((*provctx = oqsx_newprovctx(libctx, handle, corebiometh)) == NULL ) ) { 
        OQS_PROV_PRINTF("OQS PROV: error creating new provider context\n");
        ERR_raise(ERR_LIB_USER, OQSPROV_R_LIB_CREATE_ERR);
	goto end_init;
    }

    *out = oqsprovider_dispatch_table;

    // finally, warn if neither default nor fips provider are present:
    if (!OSSL_PROVIDER_available(libctx, "default") && !OSSL_PROVIDER_available(libctx, "fips")) {
        OQS_PROV_PRINTF("OQS PROV: Default and FIPS provider not available. Errors may result.\n");
    }
    else {
        OQS_PROV_PRINTF("OQS PROV: Default or FIPS provider available.\n");
    }
    rc = 1;

end_init:
    if (!rc) {
        OSSL_LIB_CTX_free(libctx);
        oqsprovider_teardown(*provctx);
        *provctx = NULL;
    }
    return rc;
}
