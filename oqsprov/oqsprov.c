// SPDX-License-Identifier: Apache-2.0 AND MIT

/* 
 * OQS OpenSSL 3 provider
 * 
 * Code strongly inspired by OpenSSL legacy provider.
 *
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
#define OQS_OID_CNT 68
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
"1.3.9999.6.1.1", "sphincsharaka128frobust",
"1.3.9999.6.1.2" , "p256_sphincsharaka128frobust",
"1.3.9999.6.1.3" , "rsa3072_sphincsharaka128frobust",
"1.3.9999.6.1.4", "sphincsharaka128fsimple",
"1.3.9999.6.1.5" , "p256_sphincsharaka128fsimple",
"1.3.9999.6.1.6" , "rsa3072_sphincsharaka128fsimple",
"1.3.9999.6.4.1", "sphincssha256128frobust",
"1.3.9999.6.4.2" , "p256_sphincssha256128frobust",
"1.3.9999.6.4.3" , "rsa3072_sphincssha256128frobust",
"1.3.9999.6.4.10", "sphincssha256128ssimple",
"1.3.9999.6.4.11" , "p256_sphincssha256128ssimple",
"1.3.9999.6.4.12" , "rsa3072_sphincssha256128ssimple",
"1.3.9999.6.7.4", "sphincsshake256128fsimple",
"1.3.9999.6.7.5" , "p256_sphincsshake256128fsimple",
"1.3.9999.6.7.6" , "rsa3072_sphincsshake256128fsimple",
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_END
};

int oqs_patch_oids(void) {
///// OQS_TEMPLATE_FRAGMENT_OID_PATCHING_START
   if (getenv("OQS_OID_DILITHIUM2")) oqs_oid_alg_list[0] = getenv("OQS_OID_DILITHIUM2");
   if (getenv("OQS_OID_P256_DILITHIUM2")) oqs_oid_alg_list[2] = getenv("OQS_OID_P256_DILITHIUM2");
   if (getenv("OQS_OID_RSA3072_DILITHIUM2")) oqs_oid_alg_list[4] = getenv("OQS_OID_RSA3072_DILITHIUM2");
   if (getenv("OQS_OID_DILITHIUM3")) oqs_oid_alg_list[6] = getenv("OQS_OID_DILITHIUM3");
   if (getenv("OQS_OID_P384_DILITHIUM3")) oqs_oid_alg_list[8] = getenv("OQS_OID_P384_DILITHIUM3");
   if (getenv("OQS_OID_DILITHIUM5")) oqs_oid_alg_list[10] = getenv("OQS_OID_DILITHIUM5");
   if (getenv("OQS_OID_P521_DILITHIUM5")) oqs_oid_alg_list[12] = getenv("OQS_OID_P521_DILITHIUM5");
   if (getenv("OQS_OID_DILITHIUM2_AES")) oqs_oid_alg_list[14] = getenv("OQS_OID_DILITHIUM2_AES");
   if (getenv("OQS_OID_P256_DILITHIUM2_AES")) oqs_oid_alg_list[16] = getenv("OQS_OID_P256_DILITHIUM2_AES");
   if (getenv("OQS_OID_RSA3072_DILITHIUM2_AES")) oqs_oid_alg_list[18] = getenv("OQS_OID_RSA3072_DILITHIUM2_AES");
   if (getenv("OQS_OID_DILITHIUM3_AES")) oqs_oid_alg_list[20] = getenv("OQS_OID_DILITHIUM3_AES");
   if (getenv("OQS_OID_P384_DILITHIUM3_AES")) oqs_oid_alg_list[22] = getenv("OQS_OID_P384_DILITHIUM3_AES");
   if (getenv("OQS_OID_DILITHIUM5_AES")) oqs_oid_alg_list[24] = getenv("OQS_OID_DILITHIUM5_AES");
   if (getenv("OQS_OID_P521_DILITHIUM5_AES")) oqs_oid_alg_list[26] = getenv("OQS_OID_P521_DILITHIUM5_AES");
   if (getenv("OQS_OID_FALCON512")) oqs_oid_alg_list[28] = getenv("OQS_OID_FALCON512");
   if (getenv("OQS_OID_P256_FALCON512")) oqs_oid_alg_list[30] = getenv("OQS_OID_P256_FALCON512");
   if (getenv("OQS_OID_RSA3072_FALCON512")) oqs_oid_alg_list[32] = getenv("OQS_OID_RSA3072_FALCON512");
   if (getenv("OQS_OID_FALCON1024")) oqs_oid_alg_list[34] = getenv("OQS_OID_FALCON1024");
   if (getenv("OQS_OID_P521_FALCON1024")) oqs_oid_alg_list[36] = getenv("OQS_OID_P521_FALCON1024");
   if (getenv("OQS_OID_SPHINCSHARAKA128FROBUST")) oqs_oid_alg_list[38] = getenv("OQS_OID_SPHINCSHARAKA128FROBUST");
   if (getenv("OQS_OID_P256_SPHINCSHARAKA128FROBUST")) oqs_oid_alg_list[40] = getenv("OQS_OID_P256_SPHINCSHARAKA128FROBUST");
   if (getenv("OQS_OID_RSA3072_SPHINCSHARAKA128FROBUST")) oqs_oid_alg_list[42] = getenv("OQS_OID_RSA3072_SPHINCSHARAKA128FROBUST");
   if (getenv("OQS_OID_SPHINCSHARAKA128FSIMPLE")) oqs_oid_alg_list[44] = getenv("OQS_OID_SPHINCSHARAKA128FSIMPLE");
   if (getenv("OQS_OID_P256_SPHINCSHARAKA128FSIMPLE")) oqs_oid_alg_list[46] = getenv("OQS_OID_P256_SPHINCSHARAKA128FSIMPLE");
   if (getenv("OQS_OID_RSA3072_SPHINCSHARAKA128FSIMPLE")) oqs_oid_alg_list[48] = getenv("OQS_OID_RSA3072_SPHINCSHARAKA128FSIMPLE");
   if (getenv("OQS_OID_SPHINCSSHA256128FROBUST")) oqs_oid_alg_list[50] = getenv("OQS_OID_SPHINCSSHA256128FROBUST");
   if (getenv("OQS_OID_P256_SPHINCSSHA256128FROBUST")) oqs_oid_alg_list[52] = getenv("OQS_OID_P256_SPHINCSSHA256128FROBUST");
   if (getenv("OQS_OID_RSA3072_SPHINCSSHA256128FROBUST")) oqs_oid_alg_list[54] = getenv("OQS_OID_RSA3072_SPHINCSSHA256128FROBUST");
   if (getenv("OQS_OID_SPHINCSSHA256128SSIMPLE")) oqs_oid_alg_list[56] = getenv("OQS_OID_SPHINCSSHA256128SSIMPLE");
   if (getenv("OQS_OID_P256_SPHINCSSHA256128SSIMPLE")) oqs_oid_alg_list[58] = getenv("OQS_OID_P256_SPHINCSSHA256128SSIMPLE");
   if (getenv("OQS_OID_RSA3072_SPHINCSSHA256128SSIMPLE")) oqs_oid_alg_list[60] = getenv("OQS_OID_RSA3072_SPHINCSSHA256128SSIMPLE");
   if (getenv("OQS_OID_SPHINCSSHAKE256128FSIMPLE")) oqs_oid_alg_list[62] = getenv("OQS_OID_SPHINCSSHAKE256128FSIMPLE");
   if (getenv("OQS_OID_P256_SPHINCSSHAKE256128FSIMPLE")) oqs_oid_alg_list[64] = getenv("OQS_OID_P256_SPHINCSSHAKE256128FSIMPLE");
   if (getenv("OQS_OID_RSA3072_SPHINCSSHAKE256128FSIMPLE")) oqs_oid_alg_list[66] = getenv("OQS_OID_RSA3072_SPHINCSSHAKE256128FSIMPLE");
///// OQS_TEMPLATE_FRAGMENT_OID_PATCHING_END
    return 1;
}

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
#ifdef OQS_ENABLE_SIG_dilithium_2
    ALG("dilithium2", oqs_signature_functions),
    ALG("p256_dilithium2", oqs_signature_functions),
    ALG("rsa3072_dilithium2", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3
    ALG("dilithium3", oqs_signature_functions),
    ALG("p384_dilithium3", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5
    ALG("dilithium5", oqs_signature_functions),
    ALG("p521_dilithium5", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_2_aes
    ALG("dilithium2_aes", oqs_signature_functions),
    ALG("p256_dilithium2_aes", oqs_signature_functions),
    ALG("rsa3072_dilithium2_aes", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3_aes
    ALG("dilithium3_aes", oqs_signature_functions),
    ALG("p384_dilithium3_aes", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5_aes
    ALG("dilithium5_aes", oqs_signature_functions),
    ALG("p521_dilithium5_aes", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_512
    ALG("falcon512", oqs_signature_functions),
    ALG("p256_falcon512", oqs_signature_functions),
    ALG("rsa3072_falcon512", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
    ALG("falcon1024", oqs_signature_functions),
    ALG("p521_falcon1024", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_haraka_128f_robust
    ALG("sphincsharaka128frobust", oqs_signature_functions),
    ALG("p256_sphincsharaka128frobust", oqs_signature_functions),
    ALG("rsa3072_sphincsharaka128frobust", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_haraka_128f_simple
    ALG("sphincsharaka128fsimple", oqs_signature_functions),
    ALG("p256_sphincsharaka128fsimple", oqs_signature_functions),
    ALG("rsa3072_sphincsharaka128fsimple", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha256_128f_robust
    ALG("sphincssha256128frobust", oqs_signature_functions),
    ALG("p256_sphincssha256128frobust", oqs_signature_functions),
    ALG("rsa3072_sphincssha256128frobust", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha256_128s_simple
    ALG("sphincssha256128ssimple", oqs_signature_functions),
    ALG("p256_sphincssha256128ssimple", oqs_signature_functions),
    ALG("rsa3072_sphincssha256128ssimple", oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_shake256_128f_simple
    ALG("sphincsshake256128fsimple", oqs_signature_functions),
    ALG("p256_sphincsshake256128fsimple", oqs_signature_functions),
    ALG("rsa3072_sphincsshake256128fsimple", oqs_signature_functions),
#endif
///// OQS_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_END
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM oqsprovider_asym_kems[] = {
///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_START
#ifdef OQS_ENABLE_KEM_frodokem_640_aes
    KEMALG3(frodo640aes, 128),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
    KEMALG3(frodo640shake, 128),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
    KEMALG3(frodo976aes, 192),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
    KEMALG3(frodo976shake, 192),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
    KEMALG2(frodo1344aes, 256),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
    KEMALG2(frodo1344shake, 256),
#endif
#ifdef OQS_ENABLE_KEM_kyber_512
    KEMALG3(kyber512, 128),
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
    KEMALG3(kyber768, 192),
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
    KEMALG2(kyber1024, 256),
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    KEMALG3(bikel1, 128),
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    KEMALG3(bikel3, 192),
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
    KEMALG2(bikel5, 256),
#endif
#ifdef OQS_ENABLE_KEM_kyber_512_90s
    KEMALG3(kyber90s512, 128),
#endif
#ifdef OQS_ENABLE_KEM_kyber_768_90s
    KEMALG3(kyber90s768, 192),
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024_90s
    KEMALG2(kyber90s1024, 256),
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
    KEMALG3(hqc128, 128),
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
    KEMALG3(hqc192, 192),
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
    KEMALG2(hqc256, 256),
#endif
///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_END
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM oqsprovider_keymgmt[] = {
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
#ifdef OQS_ENABLE_SIG_dilithium_2
    ALG("dilithium2", oqs_dilithium2_keymgmt_functions),
    ALG("p256_dilithium2", oqs_p256_dilithium2_keymgmt_functions),
    ALG("rsa3072_dilithium2", oqs_rsa3072_dilithium2_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3
    ALG("dilithium3", oqs_dilithium3_keymgmt_functions),
    ALG("p384_dilithium3", oqs_p384_dilithium3_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5
    ALG("dilithium5", oqs_dilithium5_keymgmt_functions),
    ALG("p521_dilithium5", oqs_p521_dilithium5_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_2_aes
    ALG("dilithium2_aes", oqs_dilithium2_aes_keymgmt_functions),
    ALG("p256_dilithium2_aes", oqs_p256_dilithium2_aes_keymgmt_functions),
    ALG("rsa3072_dilithium2_aes", oqs_rsa3072_dilithium2_aes_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3_aes
    ALG("dilithium3_aes", oqs_dilithium3_aes_keymgmt_functions),
    ALG("p384_dilithium3_aes", oqs_p384_dilithium3_aes_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5_aes
    ALG("dilithium5_aes", oqs_dilithium5_aes_keymgmt_functions),
    ALG("p521_dilithium5_aes", oqs_p521_dilithium5_aes_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_512
    ALG("falcon512", oqs_falcon512_keymgmt_functions),
    ALG("p256_falcon512", oqs_p256_falcon512_keymgmt_functions),
    ALG("rsa3072_falcon512", oqs_rsa3072_falcon512_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
    ALG("falcon1024", oqs_falcon1024_keymgmt_functions),
    ALG("p521_falcon1024", oqs_p521_falcon1024_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_haraka_128f_robust
    ALG("sphincsharaka128frobust", oqs_sphincsharaka128frobust_keymgmt_functions),
    ALG("p256_sphincsharaka128frobust", oqs_p256_sphincsharaka128frobust_keymgmt_functions),
    ALG("rsa3072_sphincsharaka128frobust", oqs_rsa3072_sphincsharaka128frobust_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_haraka_128f_simple
    ALG("sphincsharaka128fsimple", oqs_sphincsharaka128fsimple_keymgmt_functions),
    ALG("p256_sphincsharaka128fsimple", oqs_p256_sphincsharaka128fsimple_keymgmt_functions),
    ALG("rsa3072_sphincsharaka128fsimple", oqs_rsa3072_sphincsharaka128fsimple_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha256_128f_robust
    ALG("sphincssha256128frobust", oqs_sphincssha256128frobust_keymgmt_functions),
    ALG("p256_sphincssha256128frobust", oqs_p256_sphincssha256128frobust_keymgmt_functions),
    ALG("rsa3072_sphincssha256128frobust", oqs_rsa3072_sphincssha256128frobust_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha256_128s_simple
    ALG("sphincssha256128ssimple", oqs_sphincssha256128ssimple_keymgmt_functions),
    ALG("p256_sphincssha256128ssimple", oqs_p256_sphincssha256128ssimple_keymgmt_functions),
    ALG("rsa3072_sphincssha256128ssimple", oqs_rsa3072_sphincssha256128ssimple_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_shake256_128f_simple
    ALG("sphincsshake256128fsimple", oqs_sphincsshake256128fsimple_keymgmt_functions),
    ALG("p256_sphincsshake256128fsimple", oqs_p256_sphincsshake256128fsimple_keymgmt_functions),
    ALG("rsa3072_sphincsshake256128fsimple", oqs_rsa3072_sphincsshake256128fsimple_keymgmt_functions),
#endif

#ifdef OQS_ENABLE_KEM_frodokem_640_aes
    KEMKMALG3(frodo640aes, 128),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
    KEMKMALG3(frodo640shake, 128),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
    KEMKMALG3(frodo976aes, 192),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
    KEMKMALG3(frodo976shake, 192),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
    KEMKMALG2(frodo1344aes, 256),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
    KEMKMALG2(frodo1344shake, 256),
#endif
#ifdef OQS_ENABLE_KEM_kyber_512
    KEMKMALG3(kyber512, 128),
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
    KEMKMALG3(kyber768, 192),
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
    KEMKMALG2(kyber1024, 256),
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    KEMKMALG3(bikel1, 128),
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    KEMKMALG3(bikel3, 192),
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
    KEMKMALG2(bikel5, 256),
#endif
#ifdef OQS_ENABLE_KEM_kyber_512_90s
    KEMKMALG3(kyber90s512, 128),
#endif
#ifdef OQS_ENABLE_KEM_kyber_768_90s
    KEMKMALG3(kyber90s768, 192),
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024_90s
    KEMKMALG2(kyber90s1024, 256),
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
    KEMKMALG3(hqc128, 128),
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
    KEMKMALG3(hqc192, 192),
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
    KEMKMALG2(hqc256, 256),
#endif
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

#define OQS_PROVIDER_BUILD_INFO_STR "OQS Provider v." OQS_PROVIDER_VERSION_STR OQS_PROVIDER_COMMIT " based on liboqs v." OQS_VERSION_TEXT

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

    if (!oqs_patch_codepoints())
        return 0;

    if (!oqs_patch_oids())
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
