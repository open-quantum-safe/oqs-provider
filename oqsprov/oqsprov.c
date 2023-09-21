// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL legacy provider.
 *
 */

#include "oqs_prov.h"
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#ifdef NDEBUG
#    define OQS_PROV_PRINTF(a)
#    define OQS_PROV_PRINTF2(a, b)
#    define OQS_PROV_PRINTF3(a, b, c)
#else
#    define OQS_PROV_PRINTF(a) \
        if (getenv("OQSPROV")) \
        printf(a)
#    define OQS_PROV_PRINTF2(a, b) \
        if (getenv("OQSPROV"))     \
        printf(a, b)
#    define OQS_PROV_PRINTF3(a, b, c) \
        if (getenv("OQSPROV"))        \
        printf(a, b, c)
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
#define OQS_OID_CNT 46
const char *oqs_oid_alg_list[OQS_OID_CNT] = {
    "1.3.6.1.4.1.2.267.12.4.4",
    "dilithium2",
    "1.3.9999.2.7.5",
    "p256_dilithium2",
    "1.3.9999.2.7.6",
    "rsa3072_dilithium2",
    "1.3.6.1.4.1.2.267.12.6.5",
    "dilithium3",
    "1.3.9999.2.7.7",
    "p384_dilithium3",
    "1.3.6.1.4.1.2.267.12.8.7",
    "dilithium5",
    "1.3.9999.2.7.8",
    "p521_dilithium5",
    "1.3.9999.3.6",
    "falcon512",
    "1.3.9999.3.7",
    "p256_falcon512",
    "1.3.9999.3.8",
    "rsa3072_falcon512",
    "1.3.9999.3.9",
    "falcon1024",
    "1.3.9999.3.10",
    "p521_falcon1024",
    "1.3.9999.6.4.13",
    "sphincssha2128fsimple",
    "1.3.9999.6.4.14",
    "p256_sphincssha2128fsimple",
    "1.3.9999.6.4.15",
    "rsa3072_sphincssha2128fsimple",
    "1.3.9999.6.4.16",
    "sphincssha2128ssimple",
    "1.3.9999.6.4.17",
    "p256_sphincssha2128ssimple",
    "1.3.9999.6.4.18",
    "rsa3072_sphincssha2128ssimple",
    "1.3.9999.6.5.10",
    "sphincssha2192fsimple",
    "1.3.9999.6.5.11",
    "p384_sphincssha2192fsimple",
    "1.3.9999.6.7.13",
    "sphincsshake128fsimple",
    "1.3.9999.6.7.14",
    "p256_sphincsshake128fsimple",
    "1.3.9999.6.7.15",
    "rsa3072_sphincsshake128fsimple",
    ///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_END
};

int oqs_patch_oids(void)
{
    ///// OQS_TEMPLATE_FRAGMENT_OID_PATCHING_START
    if (getenv("OQS_OID_DILITHIUM2"))
        oqs_oid_alg_list[0] = getenv("OQS_OID_DILITHIUM2");
    if (getenv("OQS_OID_P256_DILITHIUM2"))
        oqs_oid_alg_list[2] = getenv("OQS_OID_P256_DILITHIUM2");
    if (getenv("OQS_OID_RSA3072_DILITHIUM2"))
        oqs_oid_alg_list[4] = getenv("OQS_OID_RSA3072_DILITHIUM2");
    if (getenv("OQS_OID_DILITHIUM3"))
        oqs_oid_alg_list[6] = getenv("OQS_OID_DILITHIUM3");
    if (getenv("OQS_OID_P384_DILITHIUM3"))
        oqs_oid_alg_list[8] = getenv("OQS_OID_P384_DILITHIUM3");
    if (getenv("OQS_OID_DILITHIUM5"))
        oqs_oid_alg_list[10] = getenv("OQS_OID_DILITHIUM5");
    if (getenv("OQS_OID_P521_DILITHIUM5"))
        oqs_oid_alg_list[12] = getenv("OQS_OID_P521_DILITHIUM5");
    if (getenv("OQS_OID_FALCON512"))
        oqs_oid_alg_list[14] = getenv("OQS_OID_FALCON512");
    if (getenv("OQS_OID_P256_FALCON512"))
        oqs_oid_alg_list[16] = getenv("OQS_OID_P256_FALCON512");
    if (getenv("OQS_OID_RSA3072_FALCON512"))
        oqs_oid_alg_list[18] = getenv("OQS_OID_RSA3072_FALCON512");
    if (getenv("OQS_OID_FALCON1024"))
        oqs_oid_alg_list[20] = getenv("OQS_OID_FALCON1024");
    if (getenv("OQS_OID_P521_FALCON1024"))
        oqs_oid_alg_list[22] = getenv("OQS_OID_P521_FALCON1024");
    if (getenv("OQS_OID_SPHINCSSHA2128FSIMPLE"))
        oqs_oid_alg_list[24] = getenv("OQS_OID_SPHINCSSHA2128FSIMPLE");
    if (getenv("OQS_OID_P256_SPHINCSSHA2128FSIMPLE"))
        oqs_oid_alg_list[26] = getenv("OQS_OID_P256_SPHINCSSHA2128FSIMPLE");
    if (getenv("OQS_OID_RSA3072_SPHINCSSHA2128FSIMPLE"))
        oqs_oid_alg_list[28] = getenv("OQS_OID_RSA3072_SPHINCSSHA2128FSIMPLE");
    if (getenv("OQS_OID_SPHINCSSHA2128SSIMPLE"))
        oqs_oid_alg_list[30] = getenv("OQS_OID_SPHINCSSHA2128SSIMPLE");
    if (getenv("OQS_OID_P256_SPHINCSSHA2128SSIMPLE"))
        oqs_oid_alg_list[32] = getenv("OQS_OID_P256_SPHINCSSHA2128SSIMPLE");
    if (getenv("OQS_OID_RSA3072_SPHINCSSHA2128SSIMPLE"))
        oqs_oid_alg_list[34] = getenv("OQS_OID_RSA3072_SPHINCSSHA2128SSIMPLE");
    if (getenv("OQS_OID_SPHINCSSHA2192FSIMPLE"))
        oqs_oid_alg_list[36] = getenv("OQS_OID_SPHINCSSHA2192FSIMPLE");
    if (getenv("OQS_OID_P384_SPHINCSSHA2192FSIMPLE"))
        oqs_oid_alg_list[38] = getenv("OQS_OID_P384_SPHINCSSHA2192FSIMPLE");
    if (getenv("OQS_OID_SPHINCSSHAKE128FSIMPLE"))
        oqs_oid_alg_list[40] = getenv("OQS_OID_SPHINCSSHAKE128FSIMPLE");
    if (getenv("OQS_OID_P256_SPHINCSSHAKE128FSIMPLE"))
        oqs_oid_alg_list[42] = getenv("OQS_OID_P256_SPHINCSSHAKE128FSIMPLE");
    if (getenv("OQS_OID_RSA3072_SPHINCSSHAKE128FSIMPLE"))
        oqs_oid_alg_list[44] = getenv("OQS_OID_RSA3072_SPHINCSSHAKE128FSIMPLE");
    ///// OQS_TEMPLATE_FRAGMENT_OID_PATCHING_END
    return 1;
}

#ifdef USE_ENCODING_LIB
const char *oqs_alg_encoding_list[OQS_OID_CNT] = {0};

int oqs_patch_encodings(void)
{
    ///// OQS_TEMPLATE_FRAGMENT_ENCODING_PATCHING_START
    if (getenv("OQS_ENCODING_DILITHIUM2"))
        oqs_alg_encoding_list[0] = getenv("OQS_ENCODING_DILITHIUM2");
    if (getenv("OQS_ENCODING_DILITHIUM2_ALGNAME"))
        oqs_alg_encoding_list[1] = getenv("OQS_ENCODING_DILITHIUM2_ALGNAME");
    if (getenv("OQS_ENCODING_P256_DILITHIUM2"))
        oqs_alg_encoding_list[2] = getenv("OQS_ENCODING_P256_DILITHIUM2");
    if (getenv("OQS_ENCODING_P256_DILITHIUM2_ALGNAME"))
        oqs_alg_encoding_list[3]
            = getenv("OQS_ENCODING_P256_DILITHIUM2_ALGNAME");
    if (getenv("OQS_ENCODING_RSA3072_DILITHIUM2"))
        oqs_alg_encoding_list[4] = getenv("OQS_ENCODING_RSA3072_DILITHIUM2");
    if (getenv("OQS_ENCODING_RSA3072_DILITHIUM2_ALGNAME"))
        oqs_alg_encoding_list[5]
            = getenv("OQS_ENCODING_RSA3072_DILITHIUM2_ALGNAME");
    if (getenv("OQS_ENCODING_DILITHIUM3"))
        oqs_alg_encoding_list[6] = getenv("OQS_ENCODING_DILITHIUM3");
    if (getenv("OQS_ENCODING_DILITHIUM3_ALGNAME"))
        oqs_alg_encoding_list[7] = getenv("OQS_ENCODING_DILITHIUM3_ALGNAME");
    if (getenv("OQS_ENCODING_P384_DILITHIUM3"))
        oqs_alg_encoding_list[8] = getenv("OQS_ENCODING_P384_DILITHIUM3");
    if (getenv("OQS_ENCODING_P384_DILITHIUM3_ALGNAME"))
        oqs_alg_encoding_list[9]
            = getenv("OQS_ENCODING_P384_DILITHIUM3_ALGNAME");
    if (getenv("OQS_ENCODING_DILITHIUM5"))
        oqs_alg_encoding_list[10] = getenv("OQS_ENCODING_DILITHIUM5");
    if (getenv("OQS_ENCODING_DILITHIUM5_ALGNAME"))
        oqs_alg_encoding_list[11] = getenv("OQS_ENCODING_DILITHIUM5_ALGNAME");
    if (getenv("OQS_ENCODING_P521_DILITHIUM5"))
        oqs_alg_encoding_list[12] = getenv("OQS_ENCODING_P521_DILITHIUM5");
    if (getenv("OQS_ENCODING_P521_DILITHIUM5_ALGNAME"))
        oqs_alg_encoding_list[13]
            = getenv("OQS_ENCODING_P521_DILITHIUM5_ALGNAME");
    if (getenv("OQS_ENCODING_FALCON512"))
        oqs_alg_encoding_list[14] = getenv("OQS_ENCODING_FALCON512");
    if (getenv("OQS_ENCODING_FALCON512_ALGNAME"))
        oqs_alg_encoding_list[15] = getenv("OQS_ENCODING_FALCON512_ALGNAME");
    if (getenv("OQS_ENCODING_P256_FALCON512"))
        oqs_alg_encoding_list[16] = getenv("OQS_ENCODING_P256_FALCON512");
    if (getenv("OQS_ENCODING_P256_FALCON512_ALGNAME"))
        oqs_alg_encoding_list[17]
            = getenv("OQS_ENCODING_P256_FALCON512_ALGNAME");
    if (getenv("OQS_ENCODING_RSA3072_FALCON512"))
        oqs_alg_encoding_list[18] = getenv("OQS_ENCODING_RSA3072_FALCON512");
    if (getenv("OQS_ENCODING_RSA3072_FALCON512_ALGNAME"))
        oqs_alg_encoding_list[19]
            = getenv("OQS_ENCODING_RSA3072_FALCON512_ALGNAME");
    if (getenv("OQS_ENCODING_FALCON1024"))
        oqs_alg_encoding_list[20] = getenv("OQS_ENCODING_FALCON1024");
    if (getenv("OQS_ENCODING_FALCON1024_ALGNAME"))
        oqs_alg_encoding_list[21] = getenv("OQS_ENCODING_FALCON1024_ALGNAME");
    if (getenv("OQS_ENCODING_P521_FALCON1024"))
        oqs_alg_encoding_list[22] = getenv("OQS_ENCODING_P521_FALCON1024");
    if (getenv("OQS_ENCODING_P521_FALCON1024_ALGNAME"))
        oqs_alg_encoding_list[23]
            = getenv("OQS_ENCODING_P521_FALCON1024_ALGNAME");
    if (getenv("OQS_ENCODING_SPHINCSSHA2128FSIMPLE"))
        oqs_alg_encoding_list[24]
            = getenv("OQS_ENCODING_SPHINCSSHA2128FSIMPLE");
    if (getenv("OQS_ENCODING_SPHINCSSHA2128FSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[25]
            = getenv("OQS_ENCODING_SPHINCSSHA2128FSIMPLE_ALGNAME");
    if (getenv("OQS_ENCODING_P256_SPHINCSSHA2128FSIMPLE"))
        oqs_alg_encoding_list[26]
            = getenv("OQS_ENCODING_P256_SPHINCSSHA2128FSIMPLE");
    if (getenv("OQS_ENCODING_P256_SPHINCSSHA2128FSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[27]
            = getenv("OQS_ENCODING_P256_SPHINCSSHA2128FSIMPLE_ALGNAME");
    if (getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128FSIMPLE"))
        oqs_alg_encoding_list[28]
            = getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128FSIMPLE");
    if (getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128FSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[29]
            = getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128FSIMPLE_ALGNAME");
    if (getenv("OQS_ENCODING_SPHINCSSHA2128SSIMPLE"))
        oqs_alg_encoding_list[30]
            = getenv("OQS_ENCODING_SPHINCSSHA2128SSIMPLE");
    if (getenv("OQS_ENCODING_SPHINCSSHA2128SSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[31]
            = getenv("OQS_ENCODING_SPHINCSSHA2128SSIMPLE_ALGNAME");
    if (getenv("OQS_ENCODING_P256_SPHINCSSHA2128SSIMPLE"))
        oqs_alg_encoding_list[32]
            = getenv("OQS_ENCODING_P256_SPHINCSSHA2128SSIMPLE");
    if (getenv("OQS_ENCODING_P256_SPHINCSSHA2128SSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[33]
            = getenv("OQS_ENCODING_P256_SPHINCSSHA2128SSIMPLE_ALGNAME");
    if (getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128SSIMPLE"))
        oqs_alg_encoding_list[34]
            = getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128SSIMPLE");
    if (getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128SSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[35]
            = getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128SSIMPLE_ALGNAME");
    if (getenv("OQS_ENCODING_SPHINCSSHA2192FSIMPLE"))
        oqs_alg_encoding_list[36]
            = getenv("OQS_ENCODING_SPHINCSSHA2192FSIMPLE");
    if (getenv("OQS_ENCODING_SPHINCSSHA2192FSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[37]
            = getenv("OQS_ENCODING_SPHINCSSHA2192FSIMPLE_ALGNAME");
    if (getenv("OQS_ENCODING_P384_SPHINCSSHA2192FSIMPLE"))
        oqs_alg_encoding_list[38]
            = getenv("OQS_ENCODING_P384_SPHINCSSHA2192FSIMPLE");
    if (getenv("OQS_ENCODING_P384_SPHINCSSHA2192FSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[39]
            = getenv("OQS_ENCODING_P384_SPHINCSSHA2192FSIMPLE_ALGNAME");
    if (getenv("OQS_ENCODING_SPHINCSSHAKE128FSIMPLE"))
        oqs_alg_encoding_list[40]
            = getenv("OQS_ENCODING_SPHINCSSHAKE128FSIMPLE");
    if (getenv("OQS_ENCODING_SPHINCSSHAKE128FSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[41]
            = getenv("OQS_ENCODING_SPHINCSSHAKE128FSIMPLE_ALGNAME");
    if (getenv("OQS_ENCODING_P256_SPHINCSSHAKE128FSIMPLE"))
        oqs_alg_encoding_list[42]
            = getenv("OQS_ENCODING_P256_SPHINCSSHAKE128FSIMPLE");
    if (getenv("OQS_ENCODING_P256_SPHINCSSHAKE128FSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[43]
            = getenv("OQS_ENCODING_P256_SPHINCSSHAKE128FSIMPLE_ALGNAME");
    if (getenv("OQS_ENCODING_RSA3072_SPHINCSSHAKE128FSIMPLE"))
        oqs_alg_encoding_list[44]
            = getenv("OQS_ENCODING_RSA3072_SPHINCSSHAKE128FSIMPLE");
    if (getenv("OQS_ENCODING_RSA3072_SPHINCSSHAKE128FSIMPLE_ALGNAME"))
        oqs_alg_encoding_list[45]
            = getenv("OQS_ENCODING_RSA3072_SPHINCSSHAKE128FSIMPLE_ALGNAME");
    ///// OQS_TEMPLATE_FRAGMENT_ENCODING_PATCHING_END
    return 1;
}
#endif

#define SIGALG(NAMES, SECBITS, FUNC)                                          \
    {                                                                         \
        NAMES, "provider=oqsprovider,oqsprovider.security_bits=" #SECBITS "", \
            FUNC                                                              \
    }
#define KEMBASEALG(NAMES, SECBITS)                                  \
    {"" #NAMES "",                                                  \
     "provider=oqsprovider,oqsprovider.security_bits=" #SECBITS "", \
     oqs_generic_kem_functions},

#define KEMHYBALG(NAMES, SECBITS)                                   \
    {"" #NAMES "",                                                  \
     "provider=oqsprovider,oqsprovider.security_bits=" #SECBITS "", \
     oqs_hybrid_kem_functions},

#define KEMKMALG(NAMES, SECBITS)                                    \
    {"" #NAMES "",                                                  \
     "provider=oqsprovider,oqsprovider.security_bits=" #SECBITS "", \
     oqs_##NAMES##_keymgmt_functions},

#define KEMKMHYBALG(NAMES, SECBITS, HYBTYPE)                        \
    {"" #NAMES "",                                                  \
     "provider=oqsprovider,oqsprovider.security_bits=" #SECBITS "", \
     oqs_##HYBTYPE##_##NAMES##_keymgmt_functions},

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM oqsprovider_param_types[]
    = {OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
       OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
       OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
       OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
       OSSL_PARAM_END};

static const OSSL_ALGORITHM oqsprovider_signatures[] = {
///// OQS_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_START
#ifdef OQS_ENABLE_SIG_dilithium_2
    SIGALG("dilithium2", 128, oqs_signature_functions),
    SIGALG("p256_dilithium2", 128, oqs_signature_functions),
    SIGALG("rsa3072_dilithium2", 128, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3
    SIGALG("dilithium3", 192, oqs_signature_functions),
    SIGALG("p384_dilithium3", 192, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5
    SIGALG("dilithium5", 256, oqs_signature_functions),
    SIGALG("p521_dilithium5", 256, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_512
    SIGALG("falcon512", 128, oqs_signature_functions),
    SIGALG("p256_falcon512", 128, oqs_signature_functions),
    SIGALG("rsa3072_falcon512", 128, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
    SIGALG("falcon1024", 256, oqs_signature_functions),
    SIGALG("p521_falcon1024", 256, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128f_simple
    SIGALG("sphincssha2128fsimple", 128, oqs_signature_functions),
    SIGALG("p256_sphincssha2128fsimple", 128, oqs_signature_functions),
    SIGALG("rsa3072_sphincssha2128fsimple", 128, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128s_simple
    SIGALG("sphincssha2128ssimple", 128, oqs_signature_functions),
    SIGALG("p256_sphincssha2128ssimple", 128, oqs_signature_functions),
    SIGALG("rsa3072_sphincssha2128ssimple", 128, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_192f_simple
    SIGALG("sphincssha2192fsimple", 192, oqs_signature_functions),
    SIGALG("p384_sphincssha2192fsimple", 192, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_shake_128f_simple
    SIGALG("sphincsshake128fsimple", 128, oqs_signature_functions),
    SIGALG("p256_sphincsshake128fsimple", 128, oqs_signature_functions),
    SIGALG("rsa3072_sphincsshake128fsimple", 128, oqs_signature_functions),
#endif
    ///// OQS_TEMPLATE_FRAGMENT_SIG_FUNCTIONS_END
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM oqsprovider_asym_kems[] = {
///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_START
// clang-format off
#ifdef OQS_ENABLE_KEM_frodokem_640_aes
    KEMBASEALG(frodo640aes, 128)
    KEMHYBALG(p256_frodo640aes, 128)
    KEMHYBALG(x25519_frodo640aes, 128)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
    KEMBASEALG(frodo640shake, 128)
    KEMHYBALG(p256_frodo640shake, 128)
    KEMHYBALG(x25519_frodo640shake, 128)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
    KEMBASEALG(frodo976aes, 192)
    KEMHYBALG(p384_frodo976aes, 192)
    KEMHYBALG(x448_frodo976aes, 192)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
    KEMBASEALG(frodo976shake, 192)
    KEMHYBALG(p384_frodo976shake, 192)
    KEMHYBALG(x448_frodo976shake, 192)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
    KEMBASEALG(frodo1344aes, 256)
    KEMHYBALG(p521_frodo1344aes, 256)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
    KEMBASEALG(frodo1344shake, 256)
    KEMHYBALG(p521_frodo1344shake, 256)
#endif
#ifdef OQS_ENABLE_KEM_kyber_512
    KEMBASEALG(kyber512, 128)
    KEMHYBALG(p256_kyber512, 128)
    KEMHYBALG(x25519_kyber512, 128)
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
    KEMBASEALG(kyber768, 192)
    KEMHYBALG(p384_kyber768, 192)
    KEMHYBALG(x448_kyber768, 192)
    KEMHYBALG(x25519_kyber768, 128)
    KEMHYBALG(p256_kyber768, 128)
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
    KEMBASEALG(kyber1024, 256)
    KEMHYBALG(p521_kyber1024, 256)
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    KEMBASEALG(bikel1, 128)
    KEMHYBALG(p256_bikel1, 128)
    KEMHYBALG(x25519_bikel1, 128)
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    KEMBASEALG(bikel3, 192)
    KEMHYBALG(p384_bikel3, 192)
    KEMHYBALG(x448_bikel3, 192)
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
    KEMBASEALG(bikel5, 256)
    KEMHYBALG(p521_bikel5, 256)
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
    KEMBASEALG(hqc128, 128)
    KEMHYBALG(p256_hqc128, 128)
    KEMHYBALG(x25519_hqc128, 128)
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
    KEMBASEALG(hqc192, 192)
    KEMHYBALG(p384_hqc192, 192)
    KEMHYBALG(x448_hqc192, 192)
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
    KEMBASEALG(hqc256, 256)
    KEMHYBALG(p521_hqc256, 256)
#endif
    // clang-format on
    ///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_END
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM oqsprovider_keymgmt[] = {
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
// clang-format off

#ifdef OQS_ENABLE_SIG_dilithium_2
    SIGALG("dilithium2", 128, oqs_dilithium2_keymgmt_functions),
    SIGALG("p256_dilithium2", 128, oqs_p256_dilithium2_keymgmt_functions),
    SIGALG("rsa3072_dilithium2", 128, oqs_rsa3072_dilithium2_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3
    SIGALG("dilithium3", 192, oqs_dilithium3_keymgmt_functions),
    SIGALG("p384_dilithium3", 192, oqs_p384_dilithium3_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5
    SIGALG("dilithium5", 256, oqs_dilithium5_keymgmt_functions),
    SIGALG("p521_dilithium5", 256, oqs_p521_dilithium5_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_512
    SIGALG("falcon512", 128, oqs_falcon512_keymgmt_functions),
    SIGALG("p256_falcon512", 128, oqs_p256_falcon512_keymgmt_functions),
    SIGALG("rsa3072_falcon512", 128, oqs_rsa3072_falcon512_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
    SIGALG("falcon1024", 256, oqs_falcon1024_keymgmt_functions),
    SIGALG("p521_falcon1024", 256, oqs_p521_falcon1024_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128f_simple
    SIGALG("sphincssha2128fsimple", 128, oqs_sphincssha2128fsimple_keymgmt_functions),
    SIGALG("p256_sphincssha2128fsimple", 128, oqs_p256_sphincssha2128fsimple_keymgmt_functions),
    SIGALG("rsa3072_sphincssha2128fsimple", 128, oqs_rsa3072_sphincssha2128fsimple_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128s_simple
    SIGALG("sphincssha2128ssimple", 128, oqs_sphincssha2128ssimple_keymgmt_functions),
    SIGALG("p256_sphincssha2128ssimple", 128, oqs_p256_sphincssha2128ssimple_keymgmt_functions),
    SIGALG("rsa3072_sphincssha2128ssimple", 128, oqs_rsa3072_sphincssha2128ssimple_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_192f_simple
    SIGALG("sphincssha2192fsimple", 192, oqs_sphincssha2192fsimple_keymgmt_functions),
    SIGALG("p384_sphincssha2192fsimple", 192, oqs_p384_sphincssha2192fsimple_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_shake_128f_simple
    SIGALG("sphincsshake128fsimple", 128, oqs_sphincsshake128fsimple_keymgmt_functions),
    SIGALG("p256_sphincsshake128fsimple", 128, oqs_p256_sphincsshake128fsimple_keymgmt_functions),
    SIGALG("rsa3072_sphincsshake128fsimple", 128, oqs_rsa3072_sphincsshake128fsimple_keymgmt_functions),
#endif

#ifdef OQS_ENABLE_KEM_frodokem_640_aes
    KEMKMALG(frodo640aes, 128)

    KEMKMHYBALG(p256_frodo640aes, 128, ecp)
    KEMKMHYBALG(x25519_frodo640aes, 128, ecx)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
    KEMKMALG(frodo640shake, 128)

    KEMKMHYBALG(p256_frodo640shake, 128, ecp)
    KEMKMHYBALG(x25519_frodo640shake, 128, ecx)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
    KEMKMALG(frodo976aes, 192)

    KEMKMHYBALG(p384_frodo976aes, 192, ecp)
    KEMKMHYBALG(x448_frodo976aes, 192, ecx)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
    KEMKMALG(frodo976shake, 192)

    KEMKMHYBALG(p384_frodo976shake, 192, ecp)
    KEMKMHYBALG(x448_frodo976shake, 192, ecx)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
    KEMKMALG(frodo1344aes, 256)

    KEMKMHYBALG(p521_frodo1344aes, 256, ecp)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
    KEMKMALG(frodo1344shake, 256)

    KEMKMHYBALG(p521_frodo1344shake, 256, ecp)
#endif
#ifdef OQS_ENABLE_KEM_kyber_512
    KEMKMALG(kyber512, 128)

    KEMKMHYBALG(p256_kyber512, 128, ecp)
    KEMKMHYBALG(x25519_kyber512, 128, ecx)
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
    KEMKMALG(kyber768, 192)

    KEMKMHYBALG(p384_kyber768, 192, ecp)
    KEMKMHYBALG(x448_kyber768, 192, ecx)
    KEMKMHYBALG(x25519_kyber768, 128, ecx)
    KEMKMHYBALG(p256_kyber768, 128, ecp)
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
    KEMKMALG(kyber1024, 256)

    KEMKMHYBALG(p521_kyber1024, 256, ecp)
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    KEMKMALG(bikel1, 128)

    KEMKMHYBALG(p256_bikel1, 128, ecp)
    KEMKMHYBALG(x25519_bikel1, 128, ecx)
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    KEMKMALG(bikel3, 192)

    KEMKMHYBALG(p384_bikel3, 192, ecp)
    KEMKMHYBALG(x448_bikel3, 192, ecx)
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
    KEMKMALG(bikel5, 256)

    KEMKMHYBALG(p521_bikel5, 256, ecp)
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
    KEMKMALG(hqc128, 128)

    KEMKMHYBALG(p256_hqc128, 128, ecp)
    KEMKMHYBALG(x25519_hqc128, 128, ecx)
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
    KEMKMALG(hqc192, 192)

    KEMKMHYBALG(p384_hqc192, 192, ecp)
    KEMKMHYBALG(x448_hqc192, 192, ecx)
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
    KEMKMALG(hqc256, 256)

    KEMKMHYBALG(p521_hqc256, 256, ecp)
#endif
    // clang-format on
    ///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_END
    // ALG("x25519_sikep434", oqs_ecx_sikep434_keymgmt_functions),
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM oqsprovider_encoder[] = {
#define ENCODER_PROVIDER "oqsprovider"
#include "oqsencoders.inc"
    {NULL, NULL, NULL}
#undef ENCODER_PROVIDER
};

static const OSSL_ALGORITHM oqsprovider_decoder[] = {
#define DECODER_PROVIDER "oqsprovider"
#include "oqsdecoders.inc"
    {NULL, NULL, NULL}
#undef DECODER_PROVIDER
};

static const OSSL_PARAM *oqsprovider_gettable_params(void *provctx)
{
    return oqsprovider_param_types;
}

#define OQS_PROVIDER_BASE_BUILD_INFO_STR                           \
    "OQS Provider v." OQS_PROVIDER_VERSION_STR OQS_PROVIDER_COMMIT \
    " based on liboqs v." OQS_VERSION_TEXT

#ifdef QSC_ENCODING_VERSION_STRING
#    define OQS_PROVIDER_BUILD_INFO_STR  \
        OQS_PROVIDER_BASE_BUILD_INFO_STR \
        " using qsc-key-encoder v." QSC_ENCODING_VERSION_STRING
#else
#    define OQS_PROVIDER_BUILD_INFO_STR OQS_PROVIDER_BASE_BUILD_INFO_STR
#endif

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
        if (getenv("OQSPROV"))
            printf("Unknown operation %d requested from OQS provider\n",
                   operation_id);
    }
    return NULL;
}

static void oqsprovider_teardown(void *provctx)
{
    oqsx_freeprovctx((PROV_OQS_CTX *)provctx);
    OQS_destroy();
}

/* Functions we provide to the core */
static const OSSL_DISPATCH oqsprovider_dispatch_table[]
    = {{OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))oqsprovider_teardown},
       {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        (void (*)(void))oqsprovider_gettable_params},
       {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))oqsprovider_get_params},
       {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))oqsprovider_query},
       {OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
        (void (*)(void))oqs_provider_get_capabilities},
       {0, NULL}};

#ifdef OQS_PROVIDER_STATIC
#    define OQS_PROVIDER_ENTRYPOINT_NAME oqs_provider_init
#else
#    define OQS_PROVIDER_ENTRYPOINT_NAME OSSL_provider_init
#endif // ifdef OQS_PROVIDER_STATIC

int OQS_PROVIDER_ENTRYPOINT_NAME(const OSSL_CORE_HANDLE *handle,
                                 const OSSL_DISPATCH *in,
                                 const OSSL_DISPATCH **out, void **provctx)
{
    const OSSL_DISPATCH *orig_in = in;
    OSSL_FUNC_core_obj_create_fn *c_obj_create = NULL;

    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid = NULL;
    BIO_METHOD *corebiometh;
    OSSL_LIB_CTX *libctx = NULL;
    int i, rc = 0;
    char *opensslv;
    const char *ossl_versionp = NULL;
    OSSL_PARAM version_request[] = {{"openssl-version", OSSL_PARAM_UTF8_PTR,
                                     &opensslv, sizeof(&opensslv), 0},
                                    {NULL, 0, NULL, 0, 0}};

    OQS_init();

    if (!oqs_prov_bio_from_dispatch(in))
        goto end_init;

    if (!oqs_patch_codepoints())
        goto end_init;

    if (!oqs_patch_oids())
        goto end_init;

#ifdef USE_ENCODING_LIB
    if (!oqs_patch_encodings())
        goto end_init;
#endif

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
    if (c_obj_create == NULL || c_obj_add_sigid == NULL || c_get_params == NULL)
        goto end_init;

    // we need to know the version of the calling core to activate
    // suitable bug workarounds
    if (c_get_params(handle, version_request)) {
        ossl_versionp = *(void **)version_request[0].data;
    }

    // insert all OIDs to the global objects list
    for (i = 0; i < OQS_OID_CNT; i += 2) {
        if (!c_obj_create(handle, oqs_oid_alg_list[i], oqs_oid_alg_list[i + 1],
                          oqs_oid_alg_list[i + 1])) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
            fprintf(stderr, "error registering NID for %s\n",
                    oqs_oid_alg_list[i + 1]);
            goto end_init;
        }

        /* create object (NID) again to avoid setup corner case problems
         * see https://github.com/openssl/openssl/discussions/21903
         * Not testing for errors is intentional.
         * At least one core version hangs up; so don't do this there:
         */
        if (strcmp("3.1.0", ossl_versionp)) {
            OBJ_create(oqs_oid_alg_list[i], oqs_oid_alg_list[i + 1],
                       oqs_oid_alg_list[i + 1]);
        }

        if (!oqs_set_nid((char *)oqs_oid_alg_list[i + 1],
                         OBJ_sn2nid(oqs_oid_alg_list[i + 1]))) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
            goto end_init;
        }

        if (!c_obj_add_sigid(handle, oqs_oid_alg_list[i + 1], "",
                             oqs_oid_alg_list[i + 1])) {
            fprintf(stderr, "error registering %s with no hash\n",
                    oqs_oid_alg_list[i + 1]);
            ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
            goto end_init;
        }

        if (OBJ_sn2nid(oqs_oid_alg_list[i + 1]) != 0) {
            OQS_PROV_PRINTF3(
                "OQS PROV: successfully registered %s with NID %d\n",
                oqs_oid_alg_list[i + 1], OBJ_sn2nid(oqs_oid_alg_list[i + 1]));
        } else {
            fprintf(stderr,
                    "OQS PROV: Impossible error: NID unregistered for %s.\n",
                    oqs_oid_alg_list[i + 1]);
            ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
            goto end_init;
        }
    }

    // if libctx not yet existing, create a new one
    if (((corebiometh = oqs_bio_prov_init_bio_method()) == NULL)
        || ((libctx = OSSL_LIB_CTX_new_child(handle, orig_in)) == NULL)
        || ((*provctx = oqsx_newprovctx(libctx, handle, corebiometh))
            == NULL)) {
        OQS_PROV_PRINTF("OQS PROV: error creating new provider context\n");
        ERR_raise(ERR_LIB_USER, OQSPROV_R_LIB_CREATE_ERR);
        goto end_init;
    }

    *out = oqsprovider_dispatch_table;

    // finally, warn if neither default nor fips provider are present:
    if (!OSSL_PROVIDER_available(libctx, "default")
        && !OSSL_PROVIDER_available(libctx, "fips")) {
        OQS_PROV_PRINTF(
            "OQS PROV: Default and FIPS provider not available. Errors may result.\n");
    } else {
        OQS_PROV_PRINTF("OQS PROV: Default or FIPS provider available.\n");
    }
    rc = 1;

end_init:
    if (!rc) {
        if (ossl_versionp)
            OQS_PROV_PRINTF2(
                "oqsprovider init failed for OpenSSL core version %s\n",
                ossl_versionp);
        else
            OQS_PROV_PRINTF("oqsprovider init failed for OpenSSL\n");
        if (libctx)
            OSSL_LIB_CTX_free(libctx);
        if (provctx && *provctx) {
            oqsprovider_teardown(*provctx);
            *provctx = NULL;
        }
    }
    return rc;
}
