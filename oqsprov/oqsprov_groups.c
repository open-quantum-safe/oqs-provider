// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL common provider capabilities.
 *
 * ToDo: Interop testing.
 */

#include <assert.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
/* For TLS1_VERSION etc */
#include <openssl/ssl.h>
#include <openssl/params.h>

// internal, but useful OSSL define:
# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

//#define NISTCAT(secbits) ((secbits) == 128 ? 1 : (secbits) == 192 ? 3 : 5)
#define ECP_NAME(secbits, oqsname) \
    (secbits == 128 ? "secp256r1_" #oqsname "" : secbits == 192 ? "secp384r1_" #oqsname "" : "secp521r1_" #oqsname "")
#define ECX_NAME(secbits, oqsname) \
    (secbits == 128 ? "x25519_" #oqsname "" : "x448_" #oqsname "")

typedef struct oqs_group_constants_st {
    unsigned int group_id;           /* Group ID */
    unsigned int group_id_ecp_hyb;   /* Group ID of hybrid with ECP */
    unsigned int group_id_ecx_hyb;   /* Group ID of hybrid with ECX */
    unsigned int secbits;            /* Bits of security */
    int mintls;                      /* Minimum TLS version, -1 unsupported */
    int maxtls;                      /* Maximum TLS version (or 0 for undefined) */
    int mindtls;                     /* Minimum DTLS version, -1 unsupported */
    int maxdtls;                     /* Maximum DTLS version (or 0 for undefined) */
    int is_kem;                      /* Always set */
} OQS_GROUP_CONSTANTS;

static const OQS_GROUP_CONSTANTS oqs_group_list[] = {
    // ad-hoc assignments - take from OQS generate data structures
///// OQS_TEMPLATE_FRAGMENT_GROUP_ASSIGNMENTS_START
   { 0x0200, 0x2F00, 0x2E00, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0201, 0x2F01, 0x2E01, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0202, 0x2F02, 0x2E02, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0203, 0x2F03, 0x2E03, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0204, 0x2F04, 0x2E04, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0205, 0x2F05, 0x2E05, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0206, 0x2F06, 0x2E06, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0207, 0x2F07, 0x2E07, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x020F, 0x2F0F, 0x2E0F, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0210, 0x2F10, 0x2E10, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0211, 0x2F11, 0x2E11, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0214, 0x2F14, 0x2E14, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0215, 0x2F15, 0x2E15, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0216, 0x2F16, 0x2E16, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0217, 0x2F17, 0x2E17, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0218, 0x2F18, 0x2E18, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0219, 0x2F19, 0x2E19, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021A, 0x2F1A, 0x2E1A, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021B, 0x2F1B, 0x2E1B, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021C, 0x2F1C, 0x2E1C, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021D, 0x2F1D, 0x2E1D, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021E, 0x2F1E, 0x2E1E, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021F, 0x2F1F, 0x2E1F, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0220, 0x2F20, 0x2E20, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0221, 0x2F21, 0x2E21, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0222, 0x2F22, 0x2E22, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0223, 0x2F23, 0x2E23, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0224, 0x2F24, 0x2E24, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0229, 0x2F29, 0x2E29, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022A, 0x2F2A, 0x2E2A, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022B, 0x2F2B, 0x2E2B, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022C, 0x2F2C, 0x2E2C, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022D, 0x2F2D, 0x2E2D, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022E, 0x2F2E, 0x2E2E, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022F, 0x2F2F, 0x2E2F, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0230, 0x2F30, 0x2E30, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0231, 0x2F31, 0x2E31, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0232, 0x2F32, 0x2E32, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0233, 0x2F33, 0x2E33, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0234, 0x2F34, 0x2E34, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
///// OQS_TEMPLATE_FRAGMENT_GROUP_ASSIGNMENTS_END
};

// Adds entries for tlsname, `ecx`_tlsname and `ecp`_tlsname
#define OQS_GROUP_ENTRY(tlsname, realname, algorithm, sb, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               #tlsname, \
                               sizeof(#tlsname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               #realname, \
                               sizeof(#realname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               #algorithm, \
                               sizeof(#algorithm)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, \
                        (unsigned int *)&oqs_group_list[idx].group_id), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                        (unsigned int *)&oqs_group_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, \
                        (unsigned int *)&oqs_group_list[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, \
                        (unsigned int *)&oqs_group_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, \
                        (unsigned int *)&oqs_group_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, \
                        (unsigned int *)&oqs_group_list[idx].maxdtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, \
                        (unsigned int *)&oqs_group_list[idx].is_kem), \
        OSSL_PARAM_END \
    },                                                         \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               ECP_NAME(sb, tlsname), \
                               sizeof(ECP_NAME(sb, tlsname))), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               ECP_NAME(sb, realname), \
                               sizeof(ECP_NAME(sb, realname))), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               ECP_NAME(sb, algorithm), \
                               sizeof(ECP_NAME(sb, algorithm))), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, \
                        (unsigned int *)&oqs_group_list[idx].group_id_ecp_hyb), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                        (unsigned int *)&oqs_group_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, \
                        (unsigned int *)&oqs_group_list[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, \
                        (unsigned int *)&oqs_group_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, \
                        (unsigned int *)&oqs_group_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, \
                        (unsigned int *)&oqs_group_list[idx].maxdtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, \
                        (unsigned int *)&oqs_group_list[idx].is_kem), \
        OSSL_PARAM_END \
    }, \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               ECX_NAME(sb, tlsname), \
                               sizeof(ECX_NAME(sb, tlsname))), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               ECX_NAME(sb, realname), \
                               sizeof(ECX_NAME(sb, realname))), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               ECX_NAME(sb, algorithm), \
                               sizeof(ECX_NAME(sb, algorithm))), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, \
                        (unsigned int *)&oqs_group_list[idx].group_id_ecx_hyb), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                        (unsigned int *)&oqs_group_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, \
                        (unsigned int *)&oqs_group_list[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, \
                        (unsigned int *)&oqs_group_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, \
                        (unsigned int *)&oqs_group_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, \
                        (unsigned int *)&oqs_group_list[idx].maxdtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, \
                        (unsigned int *)&oqs_group_list[idx].is_kem), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM oqs_param_group_list[][11] = {
///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_START

    OQS_GROUP_ENTRY(frodo640aes, frodo640aes, frodo640aes, 128, 0),
    OQS_GROUP_ENTRY(frodo640shake, frodo640shake, frodo640shake, 128, 1),
    OQS_GROUP_ENTRY(frodo976aes, frodo976aes, frodo976aes, 192, 2),
    OQS_GROUP_ENTRY(frodo976shake, frodo976shake, frodo976shake, 192, 3),
    OQS_GROUP_ENTRY(frodo1344aes, frodo1344aes, frodo1344aes, 256, 4),
    OQS_GROUP_ENTRY(frodo1344shake, frodo1344shake, frodo1344shake, 256, 5),
    OQS_GROUP_ENTRY(bike1l1cpa, bike1l1cpa, bike1l1cpa, 128, 6),
    OQS_GROUP_ENTRY(bike1l3cpa, bike1l3cpa, bike1l3cpa, 192, 7),
    OQS_GROUP_ENTRY(kyber512, kyber512, kyber512, 128, 8),
    OQS_GROUP_ENTRY(kyber768, kyber768, kyber768, 192, 9),
    OQS_GROUP_ENTRY(kyber1024, kyber1024, kyber1024, 256, 10),
    OQS_GROUP_ENTRY(ntru_hps2048509, ntru_hps2048509, ntru_hps2048509, 128, 11),
    OQS_GROUP_ENTRY(ntru_hps2048677, ntru_hps2048677, ntru_hps2048677, 192, 12),
    OQS_GROUP_ENTRY(ntru_hps4096821, ntru_hps4096821, ntru_hps4096821, 256, 13),
    OQS_GROUP_ENTRY(ntru_hrss701, ntru_hrss701, ntru_hrss701, 192, 14),
    OQS_GROUP_ENTRY(lightsaber, lightsaber, lightsaber, 128, 15),
    OQS_GROUP_ENTRY(saber, saber, saber, 192, 16),
    OQS_GROUP_ENTRY(firesaber, firesaber, firesaber, 256, 17),
    OQS_GROUP_ENTRY(sidhp434, sidhp434, sidhp434, 128, 18),
    OQS_GROUP_ENTRY(sidhp503, sidhp503, sidhp503, 128, 19),
    OQS_GROUP_ENTRY(sidhp610, sidhp610, sidhp610, 192, 20),
    OQS_GROUP_ENTRY(sidhp751, sidhp751, sidhp751, 256, 21),
    OQS_GROUP_ENTRY(sikep434, sikep434, sikep434, 128, 22),
    OQS_GROUP_ENTRY(sikep503, sikep503, sikep503, 128, 23),
    OQS_GROUP_ENTRY(sikep610, sikep610, sikep610, 192, 24),
    OQS_GROUP_ENTRY(sikep751, sikep751, sikep751, 256, 25),
    OQS_GROUP_ENTRY(bike1l1fo, bike1l1fo, bike1l1fo, 128, 26),
    OQS_GROUP_ENTRY(bike1l3fo, bike1l3fo, bike1l3fo, 192, 27),
    OQS_GROUP_ENTRY(kyber90s512, kyber90s512, kyber90s512, 128, 28),
    OQS_GROUP_ENTRY(kyber90s768, kyber90s768, kyber90s768, 192, 29),
    OQS_GROUP_ENTRY(kyber90s1024, kyber90s1024, kyber90s1024, 256, 30),
    OQS_GROUP_ENTRY(hqc128, hqc128, hqc128, 128, 31),
    OQS_GROUP_ENTRY(hqc192, hqc192, hqc192, 192, 32),
    OQS_GROUP_ENTRY(hqc256, hqc256, hqc256, 256, 33),
    OQS_GROUP_ENTRY(ntrulpr653, ntrulpr653, ntrulpr653, 128, 34),
    OQS_GROUP_ENTRY(ntrulpr761, ntrulpr761, ntrulpr761, 192, 35),
    OQS_GROUP_ENTRY(ntrulpr857, ntrulpr857, ntrulpr857, 192, 36),
    OQS_GROUP_ENTRY(sntrup653, sntrup653, sntrup653, 128, 37),
    OQS_GROUP_ENTRY(sntrup761, sntrup761, sntrup761, 192, 38),
    OQS_GROUP_ENTRY(sntrup857, sntrup857, sntrup857, 192, 39),
///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_END
};

static int oqs_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    assert(OSSL_NELEM(oqs_param_group_list) == OSSL_NELEM(oqs_group_list) * 3);
    for (i = 0; i < OSSL_NELEM(oqs_param_group_list); i++) {
        if (!cb(oqs_param_group_list[i], arg))
            return 0;
    }

    return 1;
}

int oqs_provider_get_capabilities(void *provctx, const char *capability,
                              OSSL_CALLBACK *cb, void *arg)
{
    //printf("OQSPROV: get_capabilities...\n");
    if (strcasecmp(capability, "TLS-GROUP") == 0)
        return oqs_group_capability(cb, arg);

    /* We don't support this capability */
    return 0;
}
