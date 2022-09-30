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

/* Temporary oqs-provider build-enabler until OSSL enablement is up-streamed */
/* TLS-SIGALG Capability */
#define OSSL_CAPABILITY_TLS_SIGALG_NAME              "tls-sigalg-name"
#define OSSL_CAPABILITY_TLS_SIGALG_NAME_INTERNAL     "tls-sigalg-name-internal"
#define OSSL_CAPABILITY_TLS_SIGALG_ALG               "tls-sigalg-alg"
#define OSSL_CAPABILITY_TLS_SIGALG_HASHALG           "tls-sigalg-hashalg"
#define OSSL_CAPABILITY_TLS_SIGALG_OID               "tls-sigalg-oid"
#define OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT        "tls-sigalg-code-point"
#define OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS     "tls-sigalg-sec-bits"
#define OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS           "tls-min-tls"
#define OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS           "tls-max-tls"
#define OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS          "tls-min-dtls"
#define OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS          "tls-max-dtls"

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
   { 0x0200, 0x2F00, 0x2F80, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0201, 0x2F01, 0x2F81, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0202, 0x2F02, 0x2F82, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0203, 0x2F03, 0x2F83, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0204, 0x2F04, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0205, 0x2F05, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x023A, 0x2F3A, 0x2F39, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x023C, 0x2F3C, 0x2F90, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x023D, 0x2F3D, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0214, 0x2F14, 0x2F94, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0215, 0x2F15, 0x2F95, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0216, 0x2F16, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0245, 0x2F45, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0217, 0x2F17, 0x2F97, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0246, 0x2F46, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0218, 0x2F18, 0x2F98, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0219, 0x2F19, 0x2F99, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021A, 0x2F1A, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0238, 0x2F38, 0x2F37, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x023B, 0x2F3B, 0     , 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x023E, 0x2F3E, 0x2FA9, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x023F, 0x2F3F, 0x2FAA, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0240, 0x2F40, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022C, 0x2F2C, 0x2FAC, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022D, 0x2F2D, 0x2FAD, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022E, 0x2F2E, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022F, 0x2F2F, 0x2FAF, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0230, 0x2F43, 0x2FB0, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0231, 0x2F31, 0x2FB1, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0241, 0x2F41, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0232, 0x2F32, 0x2FB2, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0233, 0x2F44, 0x2FB3, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0234, 0x2F34, 0x2FB4, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0242, 0x2F42, 0     , 256, TLS1_3_VERSION, 0, -1, 0, 1 },
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
    OQS_GROUP_ENTRY(kyber512, kyber512, kyber512, 128, 6),
    OQS_GROUP_ENTRY_ECP(kyber512, kyber512, kyber512, 128, 6),
    OQS_GROUP_ENTRY_ECX(kyber512, kyber512, kyber512, 128, 6),
    OQS_GROUP_ENTRY(kyber768, kyber768, kyber768, 192, 7),
    OQS_GROUP_ENTRY_ECP(kyber768, kyber768, kyber768, 192, 7),
    OQS_GROUP_ENTRY_ECX(kyber768, kyber768, kyber768, 192, 7),
    OQS_GROUP_ENTRY(kyber1024, kyber1024, kyber1024, 256, 8),
    OQS_GROUP_ENTRY_ECP(kyber1024, kyber1024, kyber1024, 256, 8),
    OQS_GROUP_ENTRY(ntru_hps2048509, ntru_hps2048509, ntru_hps2048509, 128, 9),
    OQS_GROUP_ENTRY_ECP(ntru_hps2048509, ntru_hps2048509, ntru_hps2048509, 128, 9),
    OQS_GROUP_ENTRY_ECX(ntru_hps2048509, ntru_hps2048509, ntru_hps2048509, 128, 9),
    OQS_GROUP_ENTRY(ntru_hps2048677, ntru_hps2048677, ntru_hps2048677, 192, 10),
    OQS_GROUP_ENTRY_ECP(ntru_hps2048677, ntru_hps2048677, ntru_hps2048677, 192, 10),
    OQS_GROUP_ENTRY_ECX(ntru_hps2048677, ntru_hps2048677, ntru_hps2048677, 192, 10),
    OQS_GROUP_ENTRY(ntru_hps4096821, ntru_hps4096821, ntru_hps4096821, 256, 11),
    OQS_GROUP_ENTRY_ECP(ntru_hps4096821, ntru_hps4096821, ntru_hps4096821, 256, 11),
    OQS_GROUP_ENTRY(ntru_hps40961229, ntru_hps40961229, ntru_hps40961229, 256, 12),
    OQS_GROUP_ENTRY_ECP(ntru_hps40961229, ntru_hps40961229, ntru_hps40961229, 256, 12),
    OQS_GROUP_ENTRY(ntru_hrss701, ntru_hrss701, ntru_hrss701, 192, 13),
    OQS_GROUP_ENTRY_ECP(ntru_hrss701, ntru_hrss701, ntru_hrss701, 192, 13),
    OQS_GROUP_ENTRY_ECX(ntru_hrss701, ntru_hrss701, ntru_hrss701, 192, 13),
    OQS_GROUP_ENTRY(ntru_hrss1373, ntru_hrss1373, ntru_hrss1373, 256, 14),
    OQS_GROUP_ENTRY_ECP(ntru_hrss1373, ntru_hrss1373, ntru_hrss1373, 256, 14),
    OQS_GROUP_ENTRY(lightsaber, lightsaber, lightsaber, 128, 15),
    OQS_GROUP_ENTRY_ECP(lightsaber, lightsaber, lightsaber, 128, 15),
    OQS_GROUP_ENTRY_ECX(lightsaber, lightsaber, lightsaber, 128, 15),
    OQS_GROUP_ENTRY(saber, saber, saber, 192, 16),
    OQS_GROUP_ENTRY_ECP(saber, saber, saber, 192, 16),
    OQS_GROUP_ENTRY_ECX(saber, saber, saber, 192, 16),
    OQS_GROUP_ENTRY(firesaber, firesaber, firesaber, 256, 17),
    OQS_GROUP_ENTRY_ECP(firesaber, firesaber, firesaber, 256, 17),
    OQS_GROUP_ENTRY(bikel1, bikel1, bikel1, 128, 18),
    OQS_GROUP_ENTRY_ECP(bikel1, bikel1, bikel1, 128, 18),
    OQS_GROUP_ENTRY_ECX(bikel1, bikel1, bikel1, 128, 18),
    OQS_GROUP_ENTRY(bikel3, bikel3, bikel3, 192, 19),
    OQS_GROUP_ENTRY_ECP(bikel3, bikel3, bikel3, 192, 19),
    OQS_GROUP_ENTRY(kyber90s512, kyber90s512, kyber90s512, 128, 20),
    OQS_GROUP_ENTRY_ECP(kyber90s512, kyber90s512, kyber90s512, 128, 20),
    OQS_GROUP_ENTRY_ECX(kyber90s512, kyber90s512, kyber90s512, 128, 20),
    OQS_GROUP_ENTRY(kyber90s768, kyber90s768, kyber90s768, 192, 21),
    OQS_GROUP_ENTRY_ECP(kyber90s768, kyber90s768, kyber90s768, 192, 21),
    OQS_GROUP_ENTRY_ECX(kyber90s768, kyber90s768, kyber90s768, 192, 21),
    OQS_GROUP_ENTRY(kyber90s1024, kyber90s1024, kyber90s1024, 256, 22),
    OQS_GROUP_ENTRY_ECP(kyber90s1024, kyber90s1024, kyber90s1024, 256, 22),
    OQS_GROUP_ENTRY(hqc128, hqc128, hqc128, 128, 23),
    OQS_GROUP_ENTRY_ECP(hqc128, hqc128, hqc128, 128, 23),
    OQS_GROUP_ENTRY_ECX(hqc128, hqc128, hqc128, 128, 23),
    OQS_GROUP_ENTRY(hqc192, hqc192, hqc192, 192, 24),
    OQS_GROUP_ENTRY_ECP(hqc192, hqc192, hqc192, 192, 24),
    OQS_GROUP_ENTRY_ECX(hqc192, hqc192, hqc192, 192, 24),
    OQS_GROUP_ENTRY(hqc256, hqc256, hqc256, 256, 25),
    OQS_GROUP_ENTRY_ECP(hqc256, hqc256, hqc256, 256, 25),
    OQS_GROUP_ENTRY(ntrulpr653, ntrulpr653, ntrulpr653, 128, 26),
    OQS_GROUP_ENTRY_ECP(ntrulpr653, ntrulpr653, ntrulpr653, 128, 26),
    OQS_GROUP_ENTRY_ECX(ntrulpr653, ntrulpr653, ntrulpr653, 128, 26),
    OQS_GROUP_ENTRY(ntrulpr761, ntrulpr761, ntrulpr761, 128, 27),
    OQS_GROUP_ENTRY_ECP(ntrulpr761, ntrulpr761, ntrulpr761, 128, 27),
    OQS_GROUP_ENTRY_ECX(ntrulpr761, ntrulpr761, ntrulpr761, 128, 27),
    OQS_GROUP_ENTRY(ntrulpr857, ntrulpr857, ntrulpr857, 192, 28),
    OQS_GROUP_ENTRY_ECP(ntrulpr857, ntrulpr857, ntrulpr857, 192, 28),
    OQS_GROUP_ENTRY_ECX(ntrulpr857, ntrulpr857, ntrulpr857, 192, 28),
    OQS_GROUP_ENTRY(ntrulpr1277, ntrulpr1277, ntrulpr1277, 256, 29),
    OQS_GROUP_ENTRY_ECP(ntrulpr1277, ntrulpr1277, ntrulpr1277, 256, 29),
    OQS_GROUP_ENTRY(sntrup653, sntrup653, sntrup653, 128, 30),
    OQS_GROUP_ENTRY_ECP(sntrup653, sntrup653, sntrup653, 128, 30),
    OQS_GROUP_ENTRY_ECX(sntrup653, sntrup653, sntrup653, 128, 30),
    OQS_GROUP_ENTRY(sntrup761, sntrup761, sntrup761, 128, 31),
    OQS_GROUP_ENTRY_ECP(sntrup761, sntrup761, sntrup761, 128, 31),
    OQS_GROUP_ENTRY_ECX(sntrup761, sntrup761, sntrup761, 128, 31),
    OQS_GROUP_ENTRY(sntrup857, sntrup857, sntrup857, 192, 32),
    OQS_GROUP_ENTRY_ECP(sntrup857, sntrup857, sntrup857, 192, 32),
    OQS_GROUP_ENTRY_ECX(sntrup857, sntrup857, sntrup857, 192, 32),
    OQS_GROUP_ENTRY(sntrup1277, sntrup1277, sntrup1277, 256, 33),
    OQS_GROUP_ENTRY_ECP(sntrup1277, sntrup1277, sntrup1277, 256, 33),
///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_END
};

static int oqs_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    assert(OSSL_NELEM(oqs_param_group_list) == OSSL_NELEM(oqs_group_list) * 3 - 12 /* XXX manually exclude all 256bit ECX hybrids not supported */);
    for (i = 0; i < OSSL_NELEM(oqs_param_group_list); i++) {
        if (!cb(oqs_param_group_list[i], arg))
            return 0;
    }

    return 1;
}

typedef struct oqs_sigalg_constants_st {
    unsigned int code_point;         /* Code point */
    unsigned int secbits;            /* Bits of security */
    int mintls;                      /* Minimum TLS version, -1 unsupported */
    int maxtls;                      /* Maximum TLS version (or 0 for undefined) */
    int mindtls;                     /* Minimum DTLS version, -1 unsupported */
    int maxdtls;                     /* Maximum DTLS version (or 0 for undefined) */
} OQS_SIGALG_CONSTANTS;

static const OQS_SIGALG_CONSTANTS oqs_sigalg_list[] = {
    // ad-hoc assignments - take from OQS generate data structures
///// OQS_TEMPLATE_FRAGMENT_SIGALG_ASSIGNMENTS_START
    { 0xfea0, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfea1, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfea2, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfea3, 192, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfea4, 192, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfea5, 256, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfea6, 256, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfea7, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfea8, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfea9, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfeaa, 192, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfeab, 192, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfeac, 256, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfead, 256, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe0b, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe0c, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe0d, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe0e, 256, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe0f, 256, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe96, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe97, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe98, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe1b, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe1c, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe1d, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe3c, 256, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe3d, 256, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe42, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe43, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe44, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe5e, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe5f, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe60, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe7a, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe7b, 128, TLS1_3_VERSION, 0, -1, 0 },
    { 0xfe7c, 128, TLS1_3_VERSION, 0, -1, 0 },
///// OQS_TEMPLATE_FRAGMENT_SIGALG_ASSIGNMENTS_END
};

#define OQS_SIGALG_ENTRY(tlsname, realname, algorithm, oid, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME, \
                               #tlsname, \
                               sizeof(#tlsname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME_INTERNAL, \
                               #realname, \
                               sizeof(#realname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_ALG, \
                               #algorithm, \
                               sizeof(#algorithm)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_HASHALG, "", 0) ,\
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID, \
                               #oid, \
                               sizeof(#oid)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT, \
                        (unsigned int *)&oqs_sigalg_list[idx].code_point), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS, \
                        (unsigned int *)&oqs_sigalg_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, \
                        (unsigned int *)&oqs_sigalg_list[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, \
                        (unsigned int *)&oqs_sigalg_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS, \
                        (unsigned int *)&oqs_sigalg_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS, \
                        (unsigned int *)&oqs_sigalg_list[idx].maxdtls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM oqs_param_sigalg_list[][12] = {
///// OQS_TEMPLATE_FRAGMENT_SIGALG_NAMES_START
    OQS_SIGALG_ENTRY(dilithium2, dilithium2, dilithium2, "1.3.6.1.4.1.2.267.7.4.4", 0),
    OQS_SIGALG_ENTRY(p256_dilithium2, p256_dilithium2, p256_dilithium2, "1.3.9999.2.7.1", 1),
    OQS_SIGALG_ENTRY(rsa3072_dilithium2, rsa3072_dilithium2, rsa3072_dilithium2, "1.3.9999.2.7.2", 2),
    OQS_SIGALG_ENTRY(dilithium3, dilithium3, dilithium3, "1.3.6.1.4.1.2.267.7.6.5", 3),
    OQS_SIGALG_ENTRY(p384_dilithium3, p384_dilithium3, p384_dilithium3, "1.3.9999.2.7.3", 4),
    OQS_SIGALG_ENTRY(dilithium5, dilithium5, dilithium5, "1.3.6.1.4.1.2.267.7.8.7", 5),
    OQS_SIGALG_ENTRY(p521_dilithium5, p521_dilithium5, p521_dilithium5, "1.3.9999.2.7.4", 6),
    OQS_SIGALG_ENTRY(dilithium2_aes, dilithium2_aes, dilithium2_aes, "1.3.6.1.4.1.2.267.11.4.4", 7),
    OQS_SIGALG_ENTRY(p256_dilithium2_aes, p256_dilithium2_aes, p256_dilithium2_aes, "1.3.9999.2.11.1", 8),
    OQS_SIGALG_ENTRY(rsa3072_dilithium2_aes, rsa3072_dilithium2_aes, rsa3072_dilithium2_aes, "1.3.9999.2.11.2", 9),
    OQS_SIGALG_ENTRY(dilithium3_aes, dilithium3_aes, dilithium3_aes, "1.3.6.1.4.1.2.267.11.6.5", 10),
    OQS_SIGALG_ENTRY(p384_dilithium3_aes, p384_dilithium3_aes, p384_dilithium3_aes, "1.3.9999.2.11.3", 11),
    OQS_SIGALG_ENTRY(dilithium5_aes, dilithium5_aes, dilithium5_aes, "1.3.6.1.4.1.2.267.11.8.7", 12),
    OQS_SIGALG_ENTRY(p521_dilithium5_aes, p521_dilithium5_aes, p521_dilithium5_aes, "1.3.9999.2.11.4", 13),
    OQS_SIGALG_ENTRY(falcon512, falcon512, falcon512, "1.3.9999.3.1", 14),
    OQS_SIGALG_ENTRY(p256_falcon512, p256_falcon512, p256_falcon512, "1.3.9999.3.2", 15),
    OQS_SIGALG_ENTRY(rsa3072_falcon512, rsa3072_falcon512, rsa3072_falcon512, "1.3.9999.3.3", 16),
    OQS_SIGALG_ENTRY(falcon1024, falcon1024, falcon1024, "1.3.9999.3.4", 17),
    OQS_SIGALG_ENTRY(p521_falcon1024, p521_falcon1024, p521_falcon1024, "1.3.9999.3.5", 18),
    OQS_SIGALG_ENTRY(picnicl1full, picnicl1full, picnicl1full, "1.3.6.1.4.1.311.89.2.1.7", 19),
    OQS_SIGALG_ENTRY(p256_picnicl1full, p256_picnicl1full, p256_picnicl1full, "1.3.6.1.4.1.311.89.2.1.8", 20),
    OQS_SIGALG_ENTRY(rsa3072_picnicl1full, rsa3072_picnicl1full, rsa3072_picnicl1full, "1.3.6.1.4.1.311.89.2.1.9", 21),
    OQS_SIGALG_ENTRY(picnic3l1, picnic3l1, picnic3l1, "1.3.6.1.4.1.311.89.2.1.21", 22),
    OQS_SIGALG_ENTRY(p256_picnic3l1, p256_picnic3l1, p256_picnic3l1, "1.3.6.1.4.1.311.89.2.1.22", 23),
    OQS_SIGALG_ENTRY(rsa3072_picnic3l1, rsa3072_picnic3l1, rsa3072_picnic3l1, "1.3.6.1.4.1.311.89.2.1.23", 24),
    OQS_SIGALG_ENTRY(rainbowVclassic, rainbowVclassic, rainbowVclassic, "1.3.9999.5.3.1.1", 25),
    OQS_SIGALG_ENTRY(p521_rainbowVclassic, p521_rainbowVclassic, p521_rainbowVclassic, "1.3.9999.5.3.2.1", 26),
    OQS_SIGALG_ENTRY(sphincsharaka128frobust, sphincsharaka128frobust, sphincsharaka128frobust, "1.3.9999.6.1.1", 27),
    OQS_SIGALG_ENTRY(p256_sphincsharaka128frobust, p256_sphincsharaka128frobust, p256_sphincsharaka128frobust, "1.3.9999.6.1.2", 28),
    OQS_SIGALG_ENTRY(rsa3072_sphincsharaka128frobust, rsa3072_sphincsharaka128frobust, rsa3072_sphincsharaka128frobust, "1.3.9999.6.1.3", 29),
    OQS_SIGALG_ENTRY(sphincssha256128frobust, sphincssha256128frobust, sphincssha256128frobust, "1.3.9999.6.4.1", 30),
    OQS_SIGALG_ENTRY(p256_sphincssha256128frobust, p256_sphincssha256128frobust, p256_sphincssha256128frobust, "1.3.9999.6.4.2", 31),
    OQS_SIGALG_ENTRY(rsa3072_sphincssha256128frobust, rsa3072_sphincssha256128frobust, rsa3072_sphincssha256128frobust, "1.3.9999.6.4.3", 32),
    OQS_SIGALG_ENTRY(sphincsshake256128frobust, sphincsshake256128frobust, sphincsshake256128frobust, "1.3.9999.6.7.1", 33),
    OQS_SIGALG_ENTRY(p256_sphincsshake256128frobust, p256_sphincsshake256128frobust, p256_sphincsshake256128frobust, "1.3.9999.6.7.2", 34),
    OQS_SIGALG_ENTRY(rsa3072_sphincsshake256128frobust, rsa3072_sphincsshake256128frobust, rsa3072_sphincsshake256128frobust, "1.3.9999.6.7.3", 35),
///// OQS_TEMPLATE_FRAGMENT_SIGALG_NAMES_END
};

static int oqs_sigalg_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    assert(OSSL_NELEM(oqs_param_sigalg_list) == OSSL_NELEM(oqs_sigalg_list));
    for (i = 0; i < OSSL_NELEM(oqs_param_sigalg_list); i++) {
        if (!cb(oqs_param_sigalg_list[i], arg))
            return 0;
    }

    return 1;
}

int oqs_provider_get_capabilities(void *provctx, const char *capability,
                              OSSL_CALLBACK *cb, void *arg)
{
    if (strcasecmp(capability, "TLS-GROUP") == 0)
        return oqs_group_capability(cb, arg);

    if (strcasecmp(capability, "TLS-SIGALG") == 0)
        return oqs_sigalg_capability(cb, arg);

    /* We don't support this capability */
    return 0;
}

