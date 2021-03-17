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
   { 0x0200, 0, 0x2F35, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0201, 0, 0x2F36, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0202, 0, 0x2F37, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0203, 0, 0x2F38, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0204, 0, 0x2F39, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0205, 0, 0x2F40, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0206, 0, 0x2F41, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0207, 0, 0x2F42, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x020F, 0, 0x2F26, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0210, 0, 0x2F43, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0211, 0, 0x2F44, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0214, 0, 0x2F45, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0215, 0, 0x2F46, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0216, 0, 0x2F47, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0217, 0, 0x2F48, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0218, 0, 0x2F49, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0219, 0, 0x2F50, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021A, 0, 0x2F51, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021B, 0, 0x2F52, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021C, 0, 0x2F53, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021D, 0, 0x2F54, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021E, 0, 0x2F55, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021F, 0, 0x2F27, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0220, 0, 0x2F56, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0221, 0, 0x2F57, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0222, 0, 0x2F58, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0223, 0, 0x2F28, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0224, 0, 0x2F59, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0229, 0, 0x2F60, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022A, 0, 0x2F61, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022B, 0, 0x2F62, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022C, 0, 0x2F63, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022D, 0, 0x2F64, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022E, 0, 0x2F65, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022F, 0, 0x2F66, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0230, 0, 0x2F67, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0231, 0, 0x2F68, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0232, 0, 0x2F69, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0233, 0, 0x2F70, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0234, 0, 0x2F71, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
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

    assert(OSSL_NELEM(oqs_param_group_list) == OSSL_NELEM(oqs_group_list) * 2);
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
