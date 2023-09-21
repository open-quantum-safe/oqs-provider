// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL common provider capabilities.
 *
 * ToDo: Interop testing.
 */

#include <assert.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <string.h>

/* For TLS1_VERSION etc */
#include <openssl/params.h>
#include <openssl/ssl.h>

// internal, but useful OSSL define:
#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

#include "oqs_prov.h"

typedef struct oqs_group_constants_st {
    unsigned int group_id; /* Group ID */
    unsigned int secbits;  /* Bits of security */
    int mintls;            /* Minimum TLS version, -1 unsupported */
    int maxtls;            /* Maximum TLS version (or 0 for undefined) */
    int mindtls;           /* Minimum DTLS version, -1 unsupported */
    int maxdtls;           /* Maximum DTLS version (or 0 for undefined) */
    int is_kem;            /* Always set */
} OQS_GROUP_CONSTANTS;

static OQS_GROUP_CONSTANTS oqs_group_list[] = {
    // ad-hoc assignments - take from OQS generate data structures
    ///// OQS_TEMPLATE_FRAGMENT_GROUP_ASSIGNMENTS_START
    {0x0200, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F00, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F80, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0201, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F01, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F81, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0202, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F02, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F82, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0203, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F03, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2F83, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0204, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F04, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0205, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F05, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0244, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F44, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FB0, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0245, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F45, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FB1, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FB2, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FB3, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0246, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F46, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0241, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F41, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FAE, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0242, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F42, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FAF, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x0243, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F43, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x022C, 128, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F2C, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FAC, 128, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x022D, 192, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F2D, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x2FAD, 192, TLS1_3_VERSION, 0, -1, -1, 1},
    {0x022E, 256, TLS1_3_VERSION, 0, -1, -1, 1},

    {0x2F2E, 256, TLS1_3_VERSION, 0, -1, -1, 1},
    ///// OQS_TEMPLATE_FRAGMENT_GROUP_ASSIGNMENTS_END
};

// Adds entries for tlsname, `ecx`_tlsname and `ecp`_tlsname
#define OQS_GROUP_ENTRY(tlsname, realname, algorithm, idx)                    \
    {                                                                         \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, #tlsname,      \
                               sizeof(#tlsname)),                             \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,   \
                                   #realname, sizeof(#realname)),             \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, #algorithm, \
                                   sizeof(#algorithm)),                       \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                     \
                            (unsigned int *)&oqs_group_list[idx].group_id),   \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,          \
                            (unsigned int *)&oqs_group_list[idx].secbits),    \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,                 \
                           (unsigned int *)&oqs_group_list[idx].mintls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,                 \
                           (unsigned int *)&oqs_group_list[idx].maxtls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,                \
                           (unsigned int *)&oqs_group_list[idx].mindtls),     \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,                \
                           (unsigned int *)&oqs_group_list[idx].maxdtls),     \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,                  \
                           (unsigned int *)&oqs_group_list[idx].is_kem),      \
            OSSL_PARAM_END                                                    \
    }

static const OSSL_PARAM oqs_param_group_list[][11] = {
///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_START

#ifdef OQS_ENABLE_KEM_frodokem_640_aes
    OQS_GROUP_ENTRY(frodo640aes, frodo640aes, frodo640aes, 0),

    OQS_GROUP_ENTRY(p256_frodo640aes, p256_frodo640aes, p256_frodo640aes, 1),
    OQS_GROUP_ENTRY(x25519_frodo640aes, x25519_frodo640aes, x25519_frodo640aes,
                    2),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
    OQS_GROUP_ENTRY(frodo640shake, frodo640shake, frodo640shake, 3),

    OQS_GROUP_ENTRY(p256_frodo640shake, p256_frodo640shake, p256_frodo640shake,
                    4),
    OQS_GROUP_ENTRY(x25519_frodo640shake, x25519_frodo640shake,
                    x25519_frodo640shake, 5),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
    OQS_GROUP_ENTRY(frodo976aes, frodo976aes, frodo976aes, 6),

    OQS_GROUP_ENTRY(p384_frodo976aes, p384_frodo976aes, p384_frodo976aes, 7),
    OQS_GROUP_ENTRY(x448_frodo976aes, x448_frodo976aes, x448_frodo976aes, 8),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
    OQS_GROUP_ENTRY(frodo976shake, frodo976shake, frodo976shake, 9),

    OQS_GROUP_ENTRY(p384_frodo976shake, p384_frodo976shake, p384_frodo976shake,
                    10),
    OQS_GROUP_ENTRY(x448_frodo976shake, x448_frodo976shake, x448_frodo976shake,
                    11),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
    OQS_GROUP_ENTRY(frodo1344aes, frodo1344aes, frodo1344aes, 12),

    OQS_GROUP_ENTRY(p521_frodo1344aes, p521_frodo1344aes, p521_frodo1344aes,
                    13),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
    OQS_GROUP_ENTRY(frodo1344shake, frodo1344shake, frodo1344shake, 14),

    OQS_GROUP_ENTRY(p521_frodo1344shake, p521_frodo1344shake,
                    p521_frodo1344shake, 15),
#endif
#ifdef OQS_ENABLE_KEM_kyber_512
    OQS_GROUP_ENTRY(kyber512, kyber512, kyber512, 16),

    OQS_GROUP_ENTRY(p256_kyber512, p256_kyber512, p256_kyber512, 17),
    OQS_GROUP_ENTRY(x25519_kyber512, x25519_kyber512, x25519_kyber512, 18),
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
    OQS_GROUP_ENTRY(kyber768, kyber768, kyber768, 19),

    OQS_GROUP_ENTRY(p384_kyber768, p384_kyber768, p384_kyber768, 20),
    OQS_GROUP_ENTRY(x448_kyber768, x448_kyber768, x448_kyber768, 21),
    OQS_GROUP_ENTRY(x25519_kyber768, x25519_kyber768, x25519_kyber768, 22),
    OQS_GROUP_ENTRY(p256_kyber768, p256_kyber768, p256_kyber768, 23),
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
    OQS_GROUP_ENTRY(kyber1024, kyber1024, kyber1024, 24),

    OQS_GROUP_ENTRY(p521_kyber1024, p521_kyber1024, p521_kyber1024, 25),
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    OQS_GROUP_ENTRY(bikel1, bikel1, bikel1, 26),

    OQS_GROUP_ENTRY(p256_bikel1, p256_bikel1, p256_bikel1, 27),
    OQS_GROUP_ENTRY(x25519_bikel1, x25519_bikel1, x25519_bikel1, 28),
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    OQS_GROUP_ENTRY(bikel3, bikel3, bikel3, 29),

    OQS_GROUP_ENTRY(p384_bikel3, p384_bikel3, p384_bikel3, 30),
    OQS_GROUP_ENTRY(x448_bikel3, x448_bikel3, x448_bikel3, 31),
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
    OQS_GROUP_ENTRY(bikel5, bikel5, bikel5, 32),

    OQS_GROUP_ENTRY(p521_bikel5, p521_bikel5, p521_bikel5, 33),
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
    OQS_GROUP_ENTRY(hqc128, hqc128, hqc128, 34),

    OQS_GROUP_ENTRY(p256_hqc128, p256_hqc128, p256_hqc128, 35),
    OQS_GROUP_ENTRY(x25519_hqc128, x25519_hqc128, x25519_hqc128, 36),
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
    OQS_GROUP_ENTRY(hqc192, hqc192, hqc192, 37),

    OQS_GROUP_ENTRY(p384_hqc192, p384_hqc192, p384_hqc192, 38),
    OQS_GROUP_ENTRY(x448_hqc192, x448_hqc192, x448_hqc192, 39),
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
    OQS_GROUP_ENTRY(hqc256, hqc256, hqc256, 40),

    OQS_GROUP_ENTRY(p521_hqc256, p521_hqc256, p521_hqc256, 41),
#endif
    ///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_END
};

typedef struct oqs_sigalg_constants_st {
    unsigned int code_point; /* Code point */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
} OQS_SIGALG_CONSTANTS;

static OQS_SIGALG_CONSTANTS oqs_sigalg_list[] = {
    // ad-hoc assignments - take from OQS generate data structures
    ///// OQS_TEMPLATE_FRAGMENT_SIGALG_ASSIGNMENTS_START
    {0xfed0, 128, TLS1_3_VERSION, 0}, {0xfed1, 128, TLS1_3_VERSION, 0},
    {0xfed2, 128, TLS1_3_VERSION, 0}, {0xfed3, 192, TLS1_3_VERSION, 0},
    {0xfed4, 192, TLS1_3_VERSION, 0}, {0xfed5, 256, TLS1_3_VERSION, 0},
    {0xfed6, 256, TLS1_3_VERSION, 0}, {0xfeae, 128, TLS1_3_VERSION, 0},
    {0xfeaf, 128, TLS1_3_VERSION, 0}, {0xfeb0, 128, TLS1_3_VERSION, 0},
    {0xfeb1, 256, TLS1_3_VERSION, 0}, {0xfeb2, 256, TLS1_3_VERSION, 0},
    {0xfeb3, 128, TLS1_3_VERSION, 0}, {0xfeb4, 128, TLS1_3_VERSION, 0},
    {0xfeb5, 128, TLS1_3_VERSION, 0}, {0xfeb6, 128, TLS1_3_VERSION, 0},
    {0xfeb7, 128, TLS1_3_VERSION, 0}, {0xfeb8, 128, TLS1_3_VERSION, 0},
    {0xfeb9, 192, TLS1_3_VERSION, 0}, {0xfeba, 192, TLS1_3_VERSION, 0},
    {0xfec2, 128, TLS1_3_VERSION, 0}, {0xfec3, 128, TLS1_3_VERSION, 0},
    {0xfec4, 128, TLS1_3_VERSION, 0},
    ///// OQS_TEMPLATE_FRAGMENT_SIGALG_ASSIGNMENTS_END
};

int oqs_patch_codepoints()
{

    ///// OQS_TEMPLATE_FRAGMENT_CODEPOINT_PATCHING_START
    if (getenv("OQS_CODEPOINT_FRODO640AES"))
        oqs_group_list[0].group_id = atoi(getenv("OQS_CODEPOINT_FRODO640AES"));
    if (getenv("OQS_CODEPOINT_P256_FRODO640AES"))
        oqs_group_list[1].group_id
            = atoi(getenv("OQS_CODEPOINT_P256_FRODO640AES"));
    if (getenv("OQS_CODEPOINT_X25519_FRODO640AES"))
        oqs_group_list[2].group_id
            = atoi(getenv("OQS_CODEPOINT_X25519_FRODO640AES"));
    if (getenv("OQS_CODEPOINT_FRODO640SHAKE"))
        oqs_group_list[3].group_id
            = atoi(getenv("OQS_CODEPOINT_FRODO640SHAKE"));
    if (getenv("OQS_CODEPOINT_P256_FRODO640SHAKE"))
        oqs_group_list[4].group_id
            = atoi(getenv("OQS_CODEPOINT_P256_FRODO640SHAKE"));
    if (getenv("OQS_CODEPOINT_X25519_FRODO640SHAKE"))
        oqs_group_list[5].group_id
            = atoi(getenv("OQS_CODEPOINT_X25519_FRODO640SHAKE"));
    if (getenv("OQS_CODEPOINT_FRODO976AES"))
        oqs_group_list[6].group_id = atoi(getenv("OQS_CODEPOINT_FRODO976AES"));
    if (getenv("OQS_CODEPOINT_P384_FRODO976AES"))
        oqs_group_list[7].group_id
            = atoi(getenv("OQS_CODEPOINT_P384_FRODO976AES"));
    if (getenv("OQS_CODEPOINT_X448_FRODO976AES"))
        oqs_group_list[8].group_id
            = atoi(getenv("OQS_CODEPOINT_X448_FRODO976AES"));
    if (getenv("OQS_CODEPOINT_FRODO976SHAKE"))
        oqs_group_list[9].group_id
            = atoi(getenv("OQS_CODEPOINT_FRODO976SHAKE"));
    if (getenv("OQS_CODEPOINT_P384_FRODO976SHAKE"))
        oqs_group_list[10].group_id
            = atoi(getenv("OQS_CODEPOINT_P384_FRODO976SHAKE"));
    if (getenv("OQS_CODEPOINT_X448_FRODO976SHAKE"))
        oqs_group_list[11].group_id
            = atoi(getenv("OQS_CODEPOINT_X448_FRODO976SHAKE"));
    if (getenv("OQS_CODEPOINT_FRODO1344AES"))
        oqs_group_list[12].group_id
            = atoi(getenv("OQS_CODEPOINT_FRODO1344AES"));
    if (getenv("OQS_CODEPOINT_P521_FRODO1344AES"))
        oqs_group_list[13].group_id
            = atoi(getenv("OQS_CODEPOINT_P521_FRODO1344AES"));
    if (getenv("OQS_CODEPOINT_FRODO1344SHAKE"))
        oqs_group_list[14].group_id
            = atoi(getenv("OQS_CODEPOINT_FRODO1344SHAKE"));
    if (getenv("OQS_CODEPOINT_P521_FRODO1344SHAKE"))
        oqs_group_list[15].group_id
            = atoi(getenv("OQS_CODEPOINT_P521_FRODO1344SHAKE"));
    if (getenv("OQS_CODEPOINT_KYBER512"))
        oqs_group_list[16].group_id = atoi(getenv("OQS_CODEPOINT_KYBER512"));
    if (getenv("OQS_CODEPOINT_P256_KYBER512"))
        oqs_group_list[17].group_id
            = atoi(getenv("OQS_CODEPOINT_P256_KYBER512"));
    if (getenv("OQS_CODEPOINT_X25519_KYBER512"))
        oqs_group_list[18].group_id
            = atoi(getenv("OQS_CODEPOINT_X25519_KYBER512"));
    if (getenv("OQS_CODEPOINT_KYBER768"))
        oqs_group_list[19].group_id = atoi(getenv("OQS_CODEPOINT_KYBER768"));
    if (getenv("OQS_CODEPOINT_P384_KYBER768"))
        oqs_group_list[20].group_id
            = atoi(getenv("OQS_CODEPOINT_P384_KYBER768"));
    if (getenv("OQS_CODEPOINT_X448_KYBER768"))
        oqs_group_list[21].group_id
            = atoi(getenv("OQS_CODEPOINT_X448_KYBER768"));
    if (getenv("OQS_CODEPOINT_X25519_KYBER768"))
        oqs_group_list[22].group_id
            = atoi(getenv("OQS_CODEPOINT_X25519_KYBER768"));
    if (getenv("OQS_CODEPOINT_P256_KYBER768"))
        oqs_group_list[23].group_id
            = atoi(getenv("OQS_CODEPOINT_P256_KYBER768"));
    if (getenv("OQS_CODEPOINT_KYBER1024"))
        oqs_group_list[24].group_id = atoi(getenv("OQS_CODEPOINT_KYBER1024"));
    if (getenv("OQS_CODEPOINT_P521_KYBER1024"))
        oqs_group_list[25].group_id
            = atoi(getenv("OQS_CODEPOINT_P521_KYBER1024"));
    if (getenv("OQS_CODEPOINT_BIKEL1"))
        oqs_group_list[26].group_id = atoi(getenv("OQS_CODEPOINT_BIKEL1"));
    if (getenv("OQS_CODEPOINT_P256_BIKEL1"))
        oqs_group_list[27].group_id = atoi(getenv("OQS_CODEPOINT_P256_BIKEL1"));
    if (getenv("OQS_CODEPOINT_X25519_BIKEL1"))
        oqs_group_list[28].group_id
            = atoi(getenv("OQS_CODEPOINT_X25519_BIKEL1"));
    if (getenv("OQS_CODEPOINT_BIKEL3"))
        oqs_group_list[29].group_id = atoi(getenv("OQS_CODEPOINT_BIKEL3"));
    if (getenv("OQS_CODEPOINT_P384_BIKEL3"))
        oqs_group_list[30].group_id = atoi(getenv("OQS_CODEPOINT_P384_BIKEL3"));
    if (getenv("OQS_CODEPOINT_X448_BIKEL3"))
        oqs_group_list[31].group_id = atoi(getenv("OQS_CODEPOINT_X448_BIKEL3"));
    if (getenv("OQS_CODEPOINT_BIKEL5"))
        oqs_group_list[32].group_id = atoi(getenv("OQS_CODEPOINT_BIKEL5"));
    if (getenv("OQS_CODEPOINT_P521_BIKEL5"))
        oqs_group_list[33].group_id = atoi(getenv("OQS_CODEPOINT_P521_BIKEL5"));
    if (getenv("OQS_CODEPOINT_HQC128"))
        oqs_group_list[34].group_id = atoi(getenv("OQS_CODEPOINT_HQC128"));
    if (getenv("OQS_CODEPOINT_P256_HQC128"))
        oqs_group_list[35].group_id = atoi(getenv("OQS_CODEPOINT_P256_HQC128"));
    if (getenv("OQS_CODEPOINT_X25519_HQC128"))
        oqs_group_list[36].group_id
            = atoi(getenv("OQS_CODEPOINT_X25519_HQC128"));
    if (getenv("OQS_CODEPOINT_HQC192"))
        oqs_group_list[37].group_id = atoi(getenv("OQS_CODEPOINT_HQC192"));
    if (getenv("OQS_CODEPOINT_P384_HQC192"))
        oqs_group_list[38].group_id = atoi(getenv("OQS_CODEPOINT_P384_HQC192"));
    if (getenv("OQS_CODEPOINT_X448_HQC192"))
        oqs_group_list[39].group_id = atoi(getenv("OQS_CODEPOINT_X448_HQC192"));
    if (getenv("OQS_CODEPOINT_HQC256"))
        oqs_group_list[40].group_id = atoi(getenv("OQS_CODEPOINT_HQC256"));
    if (getenv("OQS_CODEPOINT_P521_HQC256"))
        oqs_group_list[41].group_id = atoi(getenv("OQS_CODEPOINT_P521_HQC256"));

    if (getenv("OQS_CODEPOINT_DILITHIUM2"))
        oqs_sigalg_list[0].code_point
            = atoi(getenv("OQS_CODEPOINT_DILITHIUM2"));
    if (getenv("OQS_CODEPOINT_P256_DILITHIUM2"))
        oqs_sigalg_list[1].code_point
            = atoi(getenv("OQS_CODEPOINT_P256_DILITHIUM2"));
    if (getenv("OQS_CODEPOINT_RSA3072_DILITHIUM2"))
        oqs_sigalg_list[2].code_point
            = atoi(getenv("OQS_CODEPOINT_RSA3072_DILITHIUM2"));
    if (getenv("OQS_CODEPOINT_DILITHIUM3"))
        oqs_sigalg_list[3].code_point
            = atoi(getenv("OQS_CODEPOINT_DILITHIUM3"));
    if (getenv("OQS_CODEPOINT_P384_DILITHIUM3"))
        oqs_sigalg_list[4].code_point
            = atoi(getenv("OQS_CODEPOINT_P384_DILITHIUM3"));
    if (getenv("OQS_CODEPOINT_DILITHIUM5"))
        oqs_sigalg_list[5].code_point
            = atoi(getenv("OQS_CODEPOINT_DILITHIUM5"));
    if (getenv("OQS_CODEPOINT_P521_DILITHIUM5"))
        oqs_sigalg_list[6].code_point
            = atoi(getenv("OQS_CODEPOINT_P521_DILITHIUM5"));
    if (getenv("OQS_CODEPOINT_FALCON512"))
        oqs_sigalg_list[7].code_point = atoi(getenv("OQS_CODEPOINT_FALCON512"));
    if (getenv("OQS_CODEPOINT_P256_FALCON512"))
        oqs_sigalg_list[8].code_point
            = atoi(getenv("OQS_CODEPOINT_P256_FALCON512"));
    if (getenv("OQS_CODEPOINT_RSA3072_FALCON512"))
        oqs_sigalg_list[9].code_point
            = atoi(getenv("OQS_CODEPOINT_RSA3072_FALCON512"));
    if (getenv("OQS_CODEPOINT_FALCON1024"))
        oqs_sigalg_list[10].code_point
            = atoi(getenv("OQS_CODEPOINT_FALCON1024"));
    if (getenv("OQS_CODEPOINT_P521_FALCON1024"))
        oqs_sigalg_list[11].code_point
            = atoi(getenv("OQS_CODEPOINT_P521_FALCON1024"));
    if (getenv("OQS_CODEPOINT_SPHINCSSHA2128FSIMPLE"))
        oqs_sigalg_list[12].code_point
            = atoi(getenv("OQS_CODEPOINT_SPHINCSSHA2128FSIMPLE"));
    if (getenv("OQS_CODEPOINT_P256_SPHINCSSHA2128FSIMPLE"))
        oqs_sigalg_list[13].code_point
            = atoi(getenv("OQS_CODEPOINT_P256_SPHINCSSHA2128FSIMPLE"));
    if (getenv("OQS_CODEPOINT_RSA3072_SPHINCSSHA2128FSIMPLE"))
        oqs_sigalg_list[14].code_point
            = atoi(getenv("OQS_CODEPOINT_RSA3072_SPHINCSSHA2128FSIMPLE"));
    if (getenv("OQS_CODEPOINT_SPHINCSSHA2128SSIMPLE"))
        oqs_sigalg_list[15].code_point
            = atoi(getenv("OQS_CODEPOINT_SPHINCSSHA2128SSIMPLE"));
    if (getenv("OQS_CODEPOINT_P256_SPHINCSSHA2128SSIMPLE"))
        oqs_sigalg_list[16].code_point
            = atoi(getenv("OQS_CODEPOINT_P256_SPHINCSSHA2128SSIMPLE"));
    if (getenv("OQS_CODEPOINT_RSA3072_SPHINCSSHA2128SSIMPLE"))
        oqs_sigalg_list[17].code_point
            = atoi(getenv("OQS_CODEPOINT_RSA3072_SPHINCSSHA2128SSIMPLE"));
    if (getenv("OQS_CODEPOINT_SPHINCSSHA2192FSIMPLE"))
        oqs_sigalg_list[18].code_point
            = atoi(getenv("OQS_CODEPOINT_SPHINCSSHA2192FSIMPLE"));
    if (getenv("OQS_CODEPOINT_P384_SPHINCSSHA2192FSIMPLE"))
        oqs_sigalg_list[19].code_point
            = atoi(getenv("OQS_CODEPOINT_P384_SPHINCSSHA2192FSIMPLE"));
    if (getenv("OQS_CODEPOINT_SPHINCSSHAKE128FSIMPLE"))
        oqs_sigalg_list[20].code_point
            = atoi(getenv("OQS_CODEPOINT_SPHINCSSHAKE128FSIMPLE"));
    if (getenv("OQS_CODEPOINT_P256_SPHINCSSHAKE128FSIMPLE"))
        oqs_sigalg_list[21].code_point
            = atoi(getenv("OQS_CODEPOINT_P256_SPHINCSSHAKE128FSIMPLE"));
    if (getenv("OQS_CODEPOINT_RSA3072_SPHINCSSHAKE128FSIMPLE"))
        oqs_sigalg_list[22].code_point
            = atoi(getenv("OQS_CODEPOINT_RSA3072_SPHINCSSHAKE128FSIMPLE"));
    ///// OQS_TEMPLATE_FRAGMENT_CODEPOINT_PATCHING_END
    return 1;
}

static int oqs_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(oqs_param_group_list); i++) {
        if (!cb(oqs_param_group_list[i], arg))
            return 0;
    }

    return 1;
}

#ifdef OSSL_CAPABILITY_TLS_SIGALG_NAME
#    define OQS_SIGALG_ENTRY(tlsname, realname, algorithm, oid, idx)          \
        {                                                                     \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,      \
                                   #tlsname, sizeof(#tlsname)),               \
                OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME,       \
                                       #tlsname, sizeof(#tlsname)),           \
                OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID, #oid,  \
                                       sizeof(#oid)),                         \
                OSSL_PARAM_uint(                                              \
                    OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,                    \
                    (unsigned int *)&oqs_sigalg_list[idx].code_point),        \
                OSSL_PARAM_uint(                                              \
                    OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,                 \
                    (unsigned int *)&oqs_sigalg_list[idx].secbits),           \
                OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,            \
                               (unsigned int *)&oqs_sigalg_list[idx].mintls), \
                OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,            \
                               (unsigned int *)&oqs_sigalg_list[idx].maxtls), \
                OSSL_PARAM_END                                                \
        }

static const OSSL_PARAM oqs_param_sigalg_list[][12] = {
///// OQS_TEMPLATE_FRAGMENT_SIGALG_NAMES_START
#    ifdef OQS_ENABLE_SIG_dilithium_2
    OQS_SIGALG_ENTRY(dilithium2, dilithium2, dilithium2,
                     "1.3.6.1.4.1.2.267.12.4.4", 0),
    OQS_SIGALG_ENTRY(p256_dilithium2, p256_dilithium2, p256_dilithium2,
                     "1.3.9999.2.7.5", 1),
    OQS_SIGALG_ENTRY(rsa3072_dilithium2, rsa3072_dilithium2, rsa3072_dilithium2,
                     "1.3.9999.2.7.6", 2),
#    endif
#    ifdef OQS_ENABLE_SIG_dilithium_3
    OQS_SIGALG_ENTRY(dilithium3, dilithium3, dilithium3,
                     "1.3.6.1.4.1.2.267.12.6.5", 3),
    OQS_SIGALG_ENTRY(p384_dilithium3, p384_dilithium3, p384_dilithium3,
                     "1.3.9999.2.7.7", 4),
#    endif
#    ifdef OQS_ENABLE_SIG_dilithium_5
    OQS_SIGALG_ENTRY(dilithium5, dilithium5, dilithium5,
                     "1.3.6.1.4.1.2.267.12.8.7", 5),
    OQS_SIGALG_ENTRY(p521_dilithium5, p521_dilithium5, p521_dilithium5,
                     "1.3.9999.2.7.8", 6),
#    endif
#    ifdef OQS_ENABLE_SIG_falcon_512
    OQS_SIGALG_ENTRY(falcon512, falcon512, falcon512, "1.3.9999.3.6", 7),
    OQS_SIGALG_ENTRY(p256_falcon512, p256_falcon512, p256_falcon512,
                     "1.3.9999.3.7", 8),
    OQS_SIGALG_ENTRY(rsa3072_falcon512, rsa3072_falcon512, rsa3072_falcon512,
                     "1.3.9999.3.8", 9),
#    endif
#    ifdef OQS_ENABLE_SIG_falcon_1024
    OQS_SIGALG_ENTRY(falcon1024, falcon1024, falcon1024, "1.3.9999.3.9", 10),
    OQS_SIGALG_ENTRY(p521_falcon1024, p521_falcon1024, p521_falcon1024,
                     "1.3.9999.3.10", 11),
#    endif
#    ifdef OQS_ENABLE_SIG_sphincs_sha2_128f_simple
    OQS_SIGALG_ENTRY(sphincssha2128fsimple, sphincssha2128fsimple,
                     sphincssha2128fsimple, "1.3.9999.6.4.13", 12),
    OQS_SIGALG_ENTRY(p256_sphincssha2128fsimple, p256_sphincssha2128fsimple,
                     p256_sphincssha2128fsimple, "1.3.9999.6.4.14", 13),
    OQS_SIGALG_ENTRY(rsa3072_sphincssha2128fsimple,
                     rsa3072_sphincssha2128fsimple,
                     rsa3072_sphincssha2128fsimple, "1.3.9999.6.4.15", 14),
#    endif
#    ifdef OQS_ENABLE_SIG_sphincs_sha2_128s_simple
    OQS_SIGALG_ENTRY(sphincssha2128ssimple, sphincssha2128ssimple,
                     sphincssha2128ssimple, "1.3.9999.6.4.16", 15),
    OQS_SIGALG_ENTRY(p256_sphincssha2128ssimple, p256_sphincssha2128ssimple,
                     p256_sphincssha2128ssimple, "1.3.9999.6.4.17", 16),
    OQS_SIGALG_ENTRY(rsa3072_sphincssha2128ssimple,
                     rsa3072_sphincssha2128ssimple,
                     rsa3072_sphincssha2128ssimple, "1.3.9999.6.4.18", 17),
#    endif
#    ifdef OQS_ENABLE_SIG_sphincs_sha2_192f_simple
    OQS_SIGALG_ENTRY(sphincssha2192fsimple, sphincssha2192fsimple,
                     sphincssha2192fsimple, "1.3.9999.6.5.10", 18),
    OQS_SIGALG_ENTRY(p384_sphincssha2192fsimple, p384_sphincssha2192fsimple,
                     p384_sphincssha2192fsimple, "1.3.9999.6.5.11", 19),
#    endif
#    ifdef OQS_ENABLE_SIG_sphincs_shake_128f_simple
    OQS_SIGALG_ENTRY(sphincsshake128fsimple, sphincsshake128fsimple,
                     sphincsshake128fsimple, "1.3.9999.6.7.13", 20),
    OQS_SIGALG_ENTRY(p256_sphincsshake128fsimple, p256_sphincsshake128fsimple,
                     p256_sphincsshake128fsimple, "1.3.9999.6.7.14", 21),
    OQS_SIGALG_ENTRY(rsa3072_sphincsshake128fsimple,
                     rsa3072_sphincsshake128fsimple,
                     rsa3072_sphincsshake128fsimple, "1.3.9999.6.7.15", 22),
#    endif
    ///// OQS_TEMPLATE_FRAGMENT_SIGALG_NAMES_END
};

static int oqs_sigalg_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    // relaxed assertion for the case that not all algorithms are enabled in
    // liboqs:
    assert(OSSL_NELEM(oqs_param_sigalg_list) <= OSSL_NELEM(oqs_sigalg_list));
    for (i = 0; i < OSSL_NELEM(oqs_param_sigalg_list); i++) {
        if (!cb(oqs_param_sigalg_list[i], arg))
            return 0;
    }

    return 1;
}
#endif /* OSSL_CAPABILITY_TLS_SIGALG_NAME */

int oqs_provider_get_capabilities(void *provctx, const char *capability,
                                  OSSL_CALLBACK *cb, void *arg)
{
    if (strcasecmp(capability, "TLS-GROUP") == 0)
        return oqs_group_capability(cb, arg);

#ifdef OSSL_CAPABILITY_TLS_SIGALG_NAME
    if (strcasecmp(capability, "TLS-SIGALG") == 0)
        return oqs_sigalg_capability(cb, arg);
#else
#    ifndef NDEBUG
    fprintf(
        stderr,
        "Warning: OSSL_CAPABILITY_TLS_SIGALG_NAME not defined: OpenSSL version used that does not support pluggable signature capabilities.\nUpgrading OpenSSL installation recommended to enable QSC TLS signature support.\n\n");
#    endif /* NDEBUG */
#endif     /* OSSL_CAPABILITY_TLS_SIGALG_NAME */

    /* We don't support this capability */
    return 0;
}
