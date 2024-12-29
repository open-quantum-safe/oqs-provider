// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <string.h>

#include "oqs/oqs.h"
#include "test_common.h"

#define MAX_DUMMY_ENTROPY_BUFFERLEN 65536

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;

static void oqs_dummy_drbg(unsigned char *buffer, size_t bufferlen) {
    memset(buffer, 0x11, bufferlen);
    return;
}

static int oqs_load_deterministic_pseudorandom_generator(OSSL_LIB_CTX *libctx) {
    int ret = 1;
    OSSL_PARAM params[2], *p = params;
    unsigned char entropy[MAX_DUMMY_ENTROPY_BUFFERLEN];
    oqs_dummy_drbg(entropy, sizeof(entropy));

    if (!RAND_set_DRBG_type(libctx, "TEST-RAND", NULL, NULL, NULL)) {
        return 0;
    }

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                             entropy, sizeof(entropy));
    *p = OSSL_PARAM_construct_end();

    EVP_RAND_CTX *rctx_public = RAND_get0_public(libctx);
    if (!rctx_public) {
        return 0;
    }

    if (!EVP_RAND_CTX_set_params(rctx_public, params)) {
        return 0;
    }

    EVP_RAND_CTX *rctx_private = RAND_get0_private(libctx);
    if (!rctx_private) {
        return 0;
    }

    if (!EVP_RAND_CTX_set_params(rctx_private, params)) {
        return 0;
    }

    return ret;
}

static int oqs_generate_kem_elems(const char *kemalg_name, EVP_PKEY **key,
                                  unsigned char **secenc, size_t *seclen,
                                  unsigned char **secdec, unsigned char **out,
                                  size_t *outlen) {
    int testresult = 1;
    EVP_PKEY_CTX *ctx = NULL;

    // test with built-in digest only if default provider is active:
    // TBD revisit when hybrids are activated: They always need default
    // provider
    if (OSSL_PROVIDER_available(libctx, "default")) {
        testresult &= (ctx = EVP_PKEY_CTX_new_from_name(libctx, kemalg_name,
                                                        NULL)) != NULL &&
                      EVP_PKEY_keygen_init(ctx) && EVP_PKEY_generate(ctx, key);

        if (!testresult)
            goto err;
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;

        testresult &=
            (ctx = EVP_PKEY_CTX_new_from_pkey(libctx, *key, NULL)) != NULL &&
            EVP_PKEY_encapsulate_init(ctx, NULL) &&
            EVP_PKEY_encapsulate(ctx, NULL, outlen, NULL, seclen) &&
            (*out = OPENSSL_malloc(*outlen)) != NULL &&
            (*secenc = OPENSSL_malloc(*seclen)) != NULL &&
            memset(*secenc, 0x11, *seclen) != NULL &&
            (*secdec = OPENSSL_malloc(*seclen)) != NULL &&
            memset(*secdec, 0xff, *seclen) != NULL &&
            EVP_PKEY_encapsulate(ctx, *out, outlen, *secenc, seclen) &&
            EVP_PKEY_decapsulate_init(ctx, NULL) &&
            EVP_PKEY_decapsulate(ctx, *secdec, seclen, *out, *outlen) &&
            memcmp(*secenc, *secdec, *seclen) == 0;
    }

err:
    EVP_PKEY_CTX_free(ctx);
    return testresult;
}

static int oqs_generate_sig_elems(const char *sigalg_name, const char *msg,
                                  size_t msglen, EVP_PKEY **key,
                                  unsigned char **sig, size_t *siglen) {
    int testresult = 1;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *mdctx = NULL;

    // test with built-in digest only if default provider is active:
    // TBD revisit when hybrids are activated: They always need default
    // provider
    if (OSSL_PROVIDER_available(libctx, "default")) {
        testresult &=
            (ctx = EVP_PKEY_CTX_new_from_name(libctx, sigalg_name, NULL)) !=
                NULL &&
            EVP_PKEY_keygen_init(ctx) && EVP_PKEY_generate(ctx, key) &&
            (mdctx = EVP_MD_CTX_new()) != NULL &&
            EVP_DigestSignInit_ex(mdctx, NULL, "SHA512", libctx, NULL, *key,
                                  NULL) &&
            EVP_DigestSignUpdate(mdctx, msg, msglen) &&
            EVP_DigestSignFinal(mdctx, NULL, siglen) &&
            (*sig = OPENSSL_malloc(*siglen)) != NULL &&
            EVP_DigestSignFinal(mdctx, *sig, siglen) &&
            EVP_DigestVerifyInit_ex(mdctx, NULL, "SHA512", libctx, NULL, *key,
                                    NULL) &&
            EVP_DigestVerifyUpdate(mdctx, msg, msglen) &&
            EVP_DigestVerifyFinal(mdctx, *sig, *siglen);
    }

err:
    EVP_PKEY_CTX_free(ctx);
    EVP_MD_CTX_free(mdctx);
    return testresult;
}

static int test_oqs_kems_libctx(const char *kemalg_name) {
    EVP_PKEY *key1 = NULL, *key2 = NULL;
    unsigned char *out1 = NULL, *out2 = NULL;
    unsigned char *secenc1 = NULL, *secenc2 = NULL;
    unsigned char *secdec1 = NULL, *secdec2 = NULL;
    size_t outlen1, outlen2, seclen1, seclen2;

    int testresult = 1;

    if (!alg_is_enabled(kemalg_name)) {
        printf("Not testing disabled algorithm %s.\n", kemalg_name);
        return 1;
    }
    testresult &= oqs_generate_kem_elems(kemalg_name, &key1, &secenc1, &seclen1,
                                         &secdec1, &out1, &outlen1) &&
                  oqs_generate_kem_elems(kemalg_name, &key2, &secenc2, &seclen2,
                                         &secdec2, &out2, &outlen2);

    testresult &=
        EVP_PKEY_eq(key1, key2) && (seclen1 == seclen2) && (outlen1 == outlen2);
    if (!testresult)
        goto err;

    testresult &= (memcmp(secenc1, secenc2, seclen1) == 0) &&
                  (memcmp(out1, out2, outlen1) == 0);

err:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    OPENSSL_free(out1);
    OPENSSL_free(out2);
    OPENSSL_free(secenc1);
    OPENSSL_free(secenc2);
    OPENSSL_free(secdec1);
    OPENSSL_free(secdec2);
    return testresult;
}

static int test_oqs_sigs_libctx(const char *sigalg_name) {
    EVP_PKEY *key1 = NULL, *key2 = NULL;
    const char msg[] = "The quick brown fox jumps over... you know what";
    unsigned char *sig1 = NULL, *sig2 = NULL;
    size_t siglen1, siglen2;

    int testresult = 1;

    if (!alg_is_enabled(sigalg_name)) {
        printf("Not testing disabled algorithm %s.\n", sigalg_name);
        return 1;
    }
    testresult &= oqs_generate_sig_elems(sigalg_name, msg, sizeof(msg), &key1,
                                         &sig1, &siglen1) &&
                  oqs_generate_sig_elems(sigalg_name, msg, sizeof(msg), &key2,
                                         &sig2, &siglen2);

    testresult &= EVP_PKEY_eq(key1, key2) && (siglen1 == siglen2);
    if (!testresult)
        goto err;

    testresult &= memcmp(sig1, sig2, siglen1) == 0;

err:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    OPENSSL_free(sig1);
    OPENSSL_free(sig2);
    return testresult;
}

#define nelem(a) (sizeof(a) / sizeof((a)[0]))

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0, query_nocache;
    OSSL_PROVIDER *oqsprov = NULL;
    const OSSL_ALGORITHM *kemalgs, *sigalgs;

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    oqs_load_deterministic_pseudorandom_generator(libctx);
    load_oqs_provider(libctx, modulename, configfile);

    OQS_randombytes_custom_algorithm(&oqs_dummy_drbg);

    oqsprov = OSSL_PROVIDER_load(libctx, modulename);

    kemalgs =
        OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);
    if (kemalgs) {
        for (; kemalgs->algorithm_names != NULL; kemalgs++) {
            if (test_oqs_kems_libctx(kemalgs->algorithm_names)) {
                fprintf(stderr, cGREEN "  KEM test succeeded: %s" cNORM "\n",
                        kemalgs->algorithm_names);
            } else {
                fprintf(stderr, cRED "  KEM test failed: %s" cNORM "\n",
                        kemalgs->algorithm_names);
                ERR_print_errors_fp(stderr);
                errcnt++;
            }
        }
    }

    sigalgs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE,
                                            &query_nocache);
    if (sigalgs) {
        for (; sigalgs->algorithm_names != NULL; sigalgs++) {
            if (test_oqs_sigs_libctx(sigalgs->algorithm_names)) {
                fprintf(stderr,
                        cGREEN "  Signature test succeeded: %s" cNORM "\n",
                        sigalgs->algorithm_names);
            } else {
                fprintf(stderr, cRED "  Signature test failed: %s" cNORM "\n",
                        sigalgs->algorithm_names);
                ERR_print_errors_fp(stderr);
                errcnt++;
            }
        }
    }

#ifdef OQS_USE_OPENSSL
    OQS_randombytes_switch_algorithm(OQS_RAND_alg_openssl);
#else
    OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
#endif

    OSSL_LIB_CTX_free(libctx);

    TEST_ASSERT(errcnt == 0)
    return !test;
}
