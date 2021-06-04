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

#define ECP_NAME(secbits, oqsname) \
    (secbits == 128 ? "p256_" #oqsname "" : \
     secbits == 192 ? "p384_" #oqsname "" : \
                      "p521_" #oqsname "")
#define ECX_NAME(secbits, oqsname) \
    (secbits == 128 ? "x25519_" #oqsname "" : \
                        "x448_" #oqsname "")

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
   { 0x0200, 0x2F00, 0x2F40, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0201, 0x2F01, 0x2F41, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0202, 0x2F02, 0x2F42, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0203, 0x2F03, 0x2F43, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0204, 0x2F04, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0205, 0x2F05, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0206, 0x2F06, 0x2F46, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0207, 0x2F07, 0x2F47, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x020F, 0x2F0F, 0x2F26, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0210, 0x2F10, 0x2F50, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0211, 0x2F11, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0214, 0x2F14, 0x2F54, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0215, 0x2F15, 0x2F55, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0216, 0x2F16, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0217, 0x2F17, 0x2F57, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0218, 0x2F18, 0x2F58, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0219, 0x2F19, 0x2F59, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021A, 0x2F1A, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021B, 0x2F1B, 0x2F5B, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021C, 0x2F1C, 0x2F5C, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021D, 0x2F1D, 0x2F5D, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021E, 0x2F1E, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021F, 0x2F1F, 0x2F27, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0220, 0x2F20, 0x2F60, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0221, 0x2F21, 0x2F61, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0222, 0x2F22, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0223, 0x2F23, 0x2F28, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0224, 0x2F24, 0x2F64, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0229, 0x2F29, 0x2F69, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022A, 0x2F2A, 0x2F6A, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022B, 0x2F2B, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022C, 0x2F2C, 0x2F6C, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022D, 0x2F2D, 0x2F6D, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022E, 0x2F2E, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022F, 0x2F2F, 0x2F6F, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0230, 0x2F30, 0x2F70, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0231, 0x2F31, 0x2F71, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0232, 0x2F32, 0x2F72, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0233, 0x2F33, 0x2F73, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0234, 0x2F34, 0x2F74, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x01FF, 0x2FFF, 0x2FFE, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
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
    }

#define OQS_GROUP_ENTRY_ECP(tlsname, realname, algorithm, sb, idx) \
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
    }

#define OQS_GROUP_ENTRY_ECX(tlsname, realname, algorithm, sb, idx) \
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
    OQS_GROUP_ENTRY_ECP(frodo640aes, frodo640aes, frodo640aes, 128, 0),
    OQS_GROUP_ENTRY_ECX(frodo640aes, frodo640aes, frodo640aes, 128, 0),
    OQS_GROUP_ENTRY(frodo640shake, frodo640shake, frodo640shake, 128, 1),
    OQS_GROUP_ENTRY_ECP(frodo640shake, frodo640shake, frodo640shake, 128, 1),
    OQS_GROUP_ENTRY_ECX(frodo640shake, frodo640shake, frodo640shake, 128, 1),
    OQS_GROUP_ENTRY(frodo976aes, frodo976aes, frodo976aes, 192, 2),
    OQS_GROUP_ENTRY_ECP(frodo976aes, frodo976aes, frodo976aes, 192, 2),
    OQS_GROUP_ENTRY_ECX(frodo976aes, frodo976aes, frodo976aes, 192, 2),
    OQS_GROUP_ENTRY(frodo976shake, frodo976shake, frodo976shake, 192, 3),
    OQS_GROUP_ENTRY_ECP(frodo976shake, frodo976shake, frodo976shake, 192, 3),
    OQS_GROUP_ENTRY_ECX(frodo976shake, frodo976shake, frodo976shake, 192, 3),
    OQS_GROUP_ENTRY(frodo1344aes, frodo1344aes, frodo1344aes, 256, 4),
    OQS_GROUP_ENTRY_ECP(frodo1344aes, frodo1344aes, frodo1344aes, 256, 4),
    OQS_GROUP_ENTRY(frodo1344shake, frodo1344shake, frodo1344shake, 256, 5),
    OQS_GROUP_ENTRY_ECP(frodo1344shake, frodo1344shake, frodo1344shake, 256, 5),
    OQS_GROUP_ENTRY(bike1l1cpa, bike1l1cpa, bike1l1cpa, 128, 6),
    OQS_GROUP_ENTRY_ECP(bike1l1cpa, bike1l1cpa, bike1l1cpa, 128, 6),
    OQS_GROUP_ENTRY_ECX(bike1l1cpa, bike1l1cpa, bike1l1cpa, 128, 6),
    OQS_GROUP_ENTRY(bike1l3cpa, bike1l3cpa, bike1l3cpa, 192, 7),
    OQS_GROUP_ENTRY_ECP(bike1l3cpa, bike1l3cpa, bike1l3cpa, 192, 7),
    OQS_GROUP_ENTRY_ECX(bike1l3cpa, bike1l3cpa, bike1l3cpa, 192, 7),
    OQS_GROUP_ENTRY(kyber512, kyber512, kyber512, 128, 8),
    OQS_GROUP_ENTRY_ECP(kyber512, kyber512, kyber512, 128, 8),
    OQS_GROUP_ENTRY_ECX(kyber512, kyber512, kyber512, 128, 8),
    OQS_GROUP_ENTRY(kyber768, kyber768, kyber768, 192, 9),
    OQS_GROUP_ENTRY_ECP(kyber768, kyber768, kyber768, 192, 9),
    OQS_GROUP_ENTRY_ECX(kyber768, kyber768, kyber768, 192, 9),
    OQS_GROUP_ENTRY(kyber1024, kyber1024, kyber1024, 256, 10),
    OQS_GROUP_ENTRY_ECP(kyber1024, kyber1024, kyber1024, 256, 10),
    OQS_GROUP_ENTRY(ntru_hps2048509, ntru_hps2048509, ntru_hps2048509, 128, 11),
    OQS_GROUP_ENTRY_ECP(ntru_hps2048509, ntru_hps2048509, ntru_hps2048509, 128, 11),
    OQS_GROUP_ENTRY_ECX(ntru_hps2048509, ntru_hps2048509, ntru_hps2048509, 128, 11),
    OQS_GROUP_ENTRY(ntru_hps2048677, ntru_hps2048677, ntru_hps2048677, 192, 12),
    OQS_GROUP_ENTRY_ECP(ntru_hps2048677, ntru_hps2048677, ntru_hps2048677, 192, 12),
    OQS_GROUP_ENTRY_ECX(ntru_hps2048677, ntru_hps2048677, ntru_hps2048677, 192, 12),
    OQS_GROUP_ENTRY(ntru_hps4096821, ntru_hps4096821, ntru_hps4096821, 256, 13),
    OQS_GROUP_ENTRY_ECP(ntru_hps4096821, ntru_hps4096821, ntru_hps4096821, 256, 13),
    OQS_GROUP_ENTRY(ntru_hrss701, ntru_hrss701, ntru_hrss701, 192, 14),
    OQS_GROUP_ENTRY_ECP(ntru_hrss701, ntru_hrss701, ntru_hrss701, 192, 14),
    OQS_GROUP_ENTRY_ECX(ntru_hrss701, ntru_hrss701, ntru_hrss701, 192, 14),
    OQS_GROUP_ENTRY(lightsaber, lightsaber, lightsaber, 128, 15),
    OQS_GROUP_ENTRY_ECP(lightsaber, lightsaber, lightsaber, 128, 15),
    OQS_GROUP_ENTRY_ECX(lightsaber, lightsaber, lightsaber, 128, 15),
    OQS_GROUP_ENTRY(saber, saber, saber, 192, 16),
    OQS_GROUP_ENTRY_ECP(saber, saber, saber, 192, 16),
    OQS_GROUP_ENTRY_ECX(saber, saber, saber, 192, 16),
    OQS_GROUP_ENTRY(firesaber, firesaber, firesaber, 256, 17),
    OQS_GROUP_ENTRY_ECP(firesaber, firesaber, firesaber, 256, 17),
    OQS_GROUP_ENTRY(sidhp434, sidhp434, sidhp434, 128, 18),
    OQS_GROUP_ENTRY_ECP(sidhp434, sidhp434, sidhp434, 128, 18),
    OQS_GROUP_ENTRY_ECX(sidhp434, sidhp434, sidhp434, 128, 18),
    OQS_GROUP_ENTRY(sidhp503, sidhp503, sidhp503, 128, 19),
    OQS_GROUP_ENTRY_ECP(sidhp503, sidhp503, sidhp503, 128, 19),
    OQS_GROUP_ENTRY_ECX(sidhp503, sidhp503, sidhp503, 128, 19),
    OQS_GROUP_ENTRY(sidhp610, sidhp610, sidhp610, 192, 20),
    OQS_GROUP_ENTRY_ECP(sidhp610, sidhp610, sidhp610, 192, 20),
    OQS_GROUP_ENTRY_ECX(sidhp610, sidhp610, sidhp610, 192, 20),
    OQS_GROUP_ENTRY(sidhp751, sidhp751, sidhp751, 256, 21),
    OQS_GROUP_ENTRY_ECP(sidhp751, sidhp751, sidhp751, 256, 21),
    OQS_GROUP_ENTRY(sikep434, sikep434, sikep434, 128, 22),
    OQS_GROUP_ENTRY_ECP(sikep434, sikep434, sikep434, 128, 22),
    OQS_GROUP_ENTRY_ECX(sikep434, sikep434, sikep434, 128, 22),
    OQS_GROUP_ENTRY(sikep503, sikep503, sikep503, 128, 23),
    OQS_GROUP_ENTRY_ECP(sikep503, sikep503, sikep503, 128, 23),
    OQS_GROUP_ENTRY_ECX(sikep503, sikep503, sikep503, 128, 23),
    OQS_GROUP_ENTRY(sikep610, sikep610, sikep610, 192, 24),
    OQS_GROUP_ENTRY_ECP(sikep610, sikep610, sikep610, 192, 24),
    OQS_GROUP_ENTRY_ECX(sikep610, sikep610, sikep610, 192, 24),
    OQS_GROUP_ENTRY(sikep751, sikep751, sikep751, 256, 25),
    OQS_GROUP_ENTRY_ECP(sikep751, sikep751, sikep751, 256, 25),
    OQS_GROUP_ENTRY(bike1l1fo, bike1l1fo, bike1l1fo, 128, 26),
    OQS_GROUP_ENTRY_ECP(bike1l1fo, bike1l1fo, bike1l1fo, 128, 26),
    OQS_GROUP_ENTRY_ECX(bike1l1fo, bike1l1fo, bike1l1fo, 128, 26),
    OQS_GROUP_ENTRY(bike1l3fo, bike1l3fo, bike1l3fo, 192, 27),
    OQS_GROUP_ENTRY_ECP(bike1l3fo, bike1l3fo, bike1l3fo, 192, 27),
    OQS_GROUP_ENTRY_ECX(bike1l3fo, bike1l3fo, bike1l3fo, 192, 27),
    OQS_GROUP_ENTRY(kyber90s512, kyber90s512, kyber90s512, 128, 28),
    OQS_GROUP_ENTRY_ECP(kyber90s512, kyber90s512, kyber90s512, 128, 28),
    OQS_GROUP_ENTRY_ECX(kyber90s512, kyber90s512, kyber90s512, 128, 28),
    OQS_GROUP_ENTRY(kyber90s768, kyber90s768, kyber90s768, 192, 29),
    OQS_GROUP_ENTRY_ECP(kyber90s768, kyber90s768, kyber90s768, 192, 29),
    OQS_GROUP_ENTRY_ECX(kyber90s768, kyber90s768, kyber90s768, 192, 29),
    OQS_GROUP_ENTRY(kyber90s1024, kyber90s1024, kyber90s1024, 256, 30),
    OQS_GROUP_ENTRY_ECP(kyber90s1024, kyber90s1024, kyber90s1024, 256, 30),
    OQS_GROUP_ENTRY(hqc128, hqc128, hqc128, 128, 31),
    OQS_GROUP_ENTRY_ECP(hqc128, hqc128, hqc128, 128, 31),
    OQS_GROUP_ENTRY_ECX(hqc128, hqc128, hqc128, 128, 31),
    OQS_GROUP_ENTRY(hqc192, hqc192, hqc192, 192, 32),
    OQS_GROUP_ENTRY_ECP(hqc192, hqc192, hqc192, 192, 32),
    OQS_GROUP_ENTRY_ECX(hqc192, hqc192, hqc192, 192, 32),
    OQS_GROUP_ENTRY(hqc256, hqc256, hqc256, 256, 33),
    OQS_GROUP_ENTRY_ECP(hqc256, hqc256, hqc256, 256, 33),
    OQS_GROUP_ENTRY(ntrulpr653, ntrulpr653, ntrulpr653, 128, 34),
    OQS_GROUP_ENTRY_ECP(ntrulpr653, ntrulpr653, ntrulpr653, 128, 34),
    OQS_GROUP_ENTRY_ECX(ntrulpr653, ntrulpr653, ntrulpr653, 128, 34),
    OQS_GROUP_ENTRY(ntrulpr761, ntrulpr761, ntrulpr761, 192, 35),
    OQS_GROUP_ENTRY_ECP(ntrulpr761, ntrulpr761, ntrulpr761, 192, 35),
    OQS_GROUP_ENTRY_ECX(ntrulpr761, ntrulpr761, ntrulpr761, 192, 35),
    OQS_GROUP_ENTRY(ntrulpr857, ntrulpr857, ntrulpr857, 192, 36),
    OQS_GROUP_ENTRY_ECP(ntrulpr857, ntrulpr857, ntrulpr857, 192, 36),
    OQS_GROUP_ENTRY_ECX(ntrulpr857, ntrulpr857, ntrulpr857, 192, 36),
    OQS_GROUP_ENTRY(sntrup653, sntrup653, sntrup653, 128, 37),
    OQS_GROUP_ENTRY_ECP(sntrup653, sntrup653, sntrup653, 128, 37),
    OQS_GROUP_ENTRY_ECX(sntrup653, sntrup653, sntrup653, 128, 37),
    OQS_GROUP_ENTRY(sntrup761, sntrup761, sntrup761, 192, 38),
    OQS_GROUP_ENTRY_ECP(sntrup761, sntrup761, sntrup761, 192, 38),
    OQS_GROUP_ENTRY_ECX(sntrup761, sntrup761, sntrup761, 192, 38),
    OQS_GROUP_ENTRY(sntrup857, sntrup857, sntrup857, 192, 39),
    OQS_GROUP_ENTRY_ECP(sntrup857, sntrup857, sntrup857, 192, 39),
    OQS_GROUP_ENTRY_ECX(sntrup857, sntrup857, sntrup857, 192, 39),
    OQS_GROUP_ENTRY(oqs_kem_default, oqs_kem_default, oqs_kem_default, 128, 40),
    OQS_GROUP_ENTRY_ECP(oqs_kem_default, oqs_kem_default, oqs_kem_default, 128, 40),
    OQS_GROUP_ENTRY_ECX(oqs_kem_default, oqs_kem_default, oqs_kem_default, 128, 40),
///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_END
};

static int oqs_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    assert(OSSL_NELEM(oqs_param_group_list) == OSSL_NELEM(oqs_group_list) * 3 - 9);
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
