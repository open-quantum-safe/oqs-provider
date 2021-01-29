/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL common provider capabilities.
 *
 * TBC: OQS license
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

typedef struct oqs_group_constants_st {
    unsigned int group_id;   /* Group ID */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
    int mindtls;             /* Minimum DTLS version, -1 unsupported */
    int maxdtls;             /* Maximum DTLS version (or 0 for undefined) */
    int is_kem;              /* Always set */
} OQS_GROUP_CONSTANTS;

static const OQS_GROUP_CONSTANTS oqs_group_list[] = {
    // ad-hoc assignments - take from OQS generate data structures
///// OQS_TEMPLATE_FRAGMENT_GROUP_ASSIGNMENTS_START
   { 0x0200, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0201, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0202, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0203, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0204, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0205, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0206, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0207, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x020F, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0210, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0211, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0214, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0215, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0216, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0217, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0218, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0219, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021A, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021B, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021C, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021D, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021E, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x021F, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0220, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0221, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0222, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0223, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0224, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0229, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022A, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022B, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022C, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022D, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022E, 256, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x022F, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0230, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0231, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0232, 128, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0233, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
   { 0x0234, 192, TLS1_3_VERSION, 0, -1, 0, 1 },
///// OQS_TEMPLATE_FRAGMENT_GROUP_ASSIGNMENTS_END
};

#define OQS_GROUP_ENTRY(tlsname, realname, algorithm, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               tlsname, \
                               sizeof(tlsname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               realname, \
                               sizeof(realname)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               algorithm, \
                               sizeof(algorithm)), \
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

static const OSSL_PARAM oqs_param_group_list[][11] = {
///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_START

    OQS_GROUP_ENTRY("frodo640aes", "frodo640aes", "frodo640aes", 0),
    OQS_GROUP_ENTRY("frodo640shake", "frodo640shake", "frodo640shake", 1),
    OQS_GROUP_ENTRY("frodo976aes", "frodo976aes", "frodo976aes", 2),
    OQS_GROUP_ENTRY("frodo976shake", "frodo976shake", "frodo976shake", 3),
    OQS_GROUP_ENTRY("frodo1344aes", "frodo1344aes", "frodo1344aes", 4),
    OQS_GROUP_ENTRY("frodo1344shake", "frodo1344shake", "frodo1344shake", 5),
    OQS_GROUP_ENTRY("bike1l1cpa", "bike1l1cpa", "bike1l1cpa", 6),
    OQS_GROUP_ENTRY("bike1l3cpa", "bike1l3cpa", "bike1l3cpa", 7),
    OQS_GROUP_ENTRY("kyber512", "kyber512", "kyber512", 8),
    OQS_GROUP_ENTRY("kyber768", "kyber768", "kyber768", 9),
    OQS_GROUP_ENTRY("kyber1024", "kyber1024", "kyber1024", 10),
    OQS_GROUP_ENTRY("ntru_hps2048509", "ntru_hps2048509", "ntru_hps2048509", 11),
    OQS_GROUP_ENTRY("ntru_hps2048677", "ntru_hps2048677", "ntru_hps2048677", 12),
    OQS_GROUP_ENTRY("ntru_hps4096821", "ntru_hps4096821", "ntru_hps4096821", 13),
    OQS_GROUP_ENTRY("ntru_hrss701", "ntru_hrss701", "ntru_hrss701", 14),
    OQS_GROUP_ENTRY("lightsaber", "lightsaber", "lightsaber", 15),
    OQS_GROUP_ENTRY("saber", "saber", "saber", 16),
    OQS_GROUP_ENTRY("firesaber", "firesaber", "firesaber", 17),
    OQS_GROUP_ENTRY("sidhp434", "sidhp434", "sidhp434", 18),
    OQS_GROUP_ENTRY("sidhp503", "sidhp503", "sidhp503", 19),
    OQS_GROUP_ENTRY("sidhp610", "sidhp610", "sidhp610", 20),
    OQS_GROUP_ENTRY("sidhp751", "sidhp751", "sidhp751", 21),
    OQS_GROUP_ENTRY("sikep434", "sikep434", "sikep434", 22),
    OQS_GROUP_ENTRY("sikep503", "sikep503", "sikep503", 23),
    OQS_GROUP_ENTRY("sikep610", "sikep610", "sikep610", 24),
    OQS_GROUP_ENTRY("sikep751", "sikep751", "sikep751", 25),
    OQS_GROUP_ENTRY("bike1l1fo", "bike1l1fo", "bike1l1fo", 26),
    OQS_GROUP_ENTRY("bike1l3fo", "bike1l3fo", "bike1l3fo", 27),
    OQS_GROUP_ENTRY("kyber90s512", "kyber90s512", "kyber90s512", 28),
    OQS_GROUP_ENTRY("kyber90s768", "kyber90s768", "kyber90s768", 29),
    OQS_GROUP_ENTRY("kyber90s1024", "kyber90s1024", "kyber90s1024", 30),
    OQS_GROUP_ENTRY("hqc128", "hqc128", "hqc128", 31),
    OQS_GROUP_ENTRY("hqc192", "hqc192", "hqc192", 32),
    OQS_GROUP_ENTRY("hqc256", "hqc256", "hqc256", 33),
    OQS_GROUP_ENTRY("ntrulpr653", "ntrulpr653", "ntrulpr653", 34),
    OQS_GROUP_ENTRY("ntrulpr761", "ntrulpr761", "ntrulpr761", 35),
    OQS_GROUP_ENTRY("ntrulpr857", "ntrulpr857", "ntrulpr857", 36),
    OQS_GROUP_ENTRY("sntrup653", "sntrup653", "sntrup653", 37),
    OQS_GROUP_ENTRY("sntrup761", "sntrup761", "sntrup761", 38),
    OQS_GROUP_ENTRY("sntrup857", "sntrup857", "sntrup857", 39),
///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_END
};

static int oqs_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    assert(OSSL_NELEM(oqs_param_group_list) == OSSL_NELEM(oqs_group_list));
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

