// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <string.h>

#include "oqs/oqs.h"
#include "test_common.h"

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;

#define OQSPROV_PROPQ_MISSING "provider=the-missing-link"

static int test_oqs_kems(const char *kemalg_name) {
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL, *peer = NULL;
    unsigned char *out = NULL;
    unsigned char *secenc = NULL;
    unsigned char *secdec = NULL;
    unsigned char *pubkey = NULL;
    size_t outlen, seclen, publen;

    int testresult = 1;

    if (!alg_is_enabled(kemalg_name)) {
        fprintf(stderr, "Not testing disabled algorithm %s.\n", kemalg_name);
        return 1;
    }
    // test with built-in digest only if default provider is active:
    // limit testing to oqsprovider as other implementations may support
    // different key formats than what is defined by NIST
    if (OSSL_PROVIDER_available(libctx, "default")) {
        testresult &= (ctx = EVP_PKEY_CTX_new_from_name(
                           libctx, kemalg_name, OQSPROV_PROPQ)) != NULL &&
                      EVP_PKEY_keygen_init(ctx) && EVP_PKEY_generate(ctx, &key);

        if (!testresult)
            goto err;
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;

        testresult &=
            (ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, OQSPROV_PROPQ)) !=
                NULL &&
            EVP_PKEY_encapsulate_init(ctx, NULL) &&
            EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &seclen) &&
            (out = OPENSSL_malloc(outlen)) != NULL &&
            (secenc = OPENSSL_malloc(seclen)) != NULL &&
            memset(secenc, 0x11, seclen) != NULL &&
            (secdec = OPENSSL_malloc(seclen)) != NULL &&
            memset(secdec, 0xff, seclen) != NULL &&
            EVP_PKEY_encapsulate(ctx, out, &outlen, secenc, &seclen) &&
            EVP_PKEY_decapsulate_init(ctx, NULL) &&
            EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen) &&
            memcmp(secenc, secdec, seclen) == 0;
        if (!testresult)
            goto err;

        out[0] = ~out[0];
        out[outlen - 1] = ~out[outlen - 1];
        testresult &=
            memset(secdec, 0xff, seclen) != NULL &&
            EVP_PKEY_decapsulate_init(ctx, NULL) &&
            (EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen) || 1) &&
            memcmp(secenc, secdec, seclen) != 0;
        if (!testresult)
            goto err;

        // Now encapsulation from public key context
        testresult &=
            EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, NULL,
                                            0, &publen) &&
            (pubkey = OPENSSL_malloc(publen)) != NULL &&
            EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                            pubkey, publen, NULL) &&
            (peer = EVP_PKEY_new_raw_public_key_ex(
                 libctx, kemalg_name, OQSPROV_PROPQ, pubkey, publen)) != NULL;

        if (!testresult)
            goto err;
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        OPENSSL_free(out);
        out = NULL;
        OPENSSL_free(secenc);
        secenc = NULL;

        testresult &=
            (ctx = EVP_PKEY_CTX_new_from_pkey(libctx, peer, OQSPROV_PROPQ)) !=
                NULL &&
            EVP_PKEY_encapsulate_init(ctx, NULL) &&
            EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &seclen) &&
            (out = OPENSSL_malloc(outlen)) != NULL &&
            (secenc = OPENSSL_malloc(seclen)) != NULL &&
            memset(secenc, 0x11, seclen) != NULL &&
            EVP_PKEY_encapsulate(ctx, out, &outlen, secenc, &seclen);

        if (!testresult)
            goto err;
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        OPENSSL_free(secdec);
        secdec = NULL;

        testresult &=
            (ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, OQSPROV_PROPQ)) !=
                NULL &&
            EVP_PKEY_decapsulate_init(ctx, NULL) &&
            (secdec = OPENSSL_malloc(seclen)) != NULL &&
            memset(secdec, 0xff, seclen) != NULL &&
            EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen) &&
            memcmp(secenc, secdec, seclen) == 0;

        out[0] = ~out[0];
        out[outlen - 1] = ~out[outlen - 1];
        testresult &=
            memset(secdec, 0xff, seclen) != NULL &&
            EVP_PKEY_decapsulate_init(ctx, NULL) &&
            (EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen) || 1) &&
            memcmp(secenc, secdec, seclen) != 0;
    }

err:
    EVP_PKEY_free(key);
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(pubkey);
    OPENSSL_free(out);
    OPENSSL_free(secenc);
    OPENSSL_free(secdec);
    return testresult;
}

/*
 * Runs keygen + encapsulate + decapsulate for one hybrid KEM with the given
 * property query string. Returns 1 on success, 0 on failure.
 */
static int test_oqs_hybrid_kems_with_propq(const char *kemalg_name,
                                           const char *propq) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL, *peer = NULL;
    unsigned char *out = NULL;
    unsigned char *secenc = NULL;
    unsigned char *secdec = NULL;
    unsigned char *pubkey = NULL;
    size_t outlen, seclen, publen;
    int testresult = 0;

    if (!OSSL_PROVIDER_available(libctx, "default"))
        return 0;

    ctx = EVP_PKEY_CTX_new_from_name(libctx, kemalg_name, propq);
    if (ctx == NULL)
        return 0;
    if (!EVP_PKEY_keygen_init(ctx) || !EVP_PKEY_generate(ctx, &key)) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, propq);
    if (ctx == NULL)
        goto err;
    if (!EVP_PKEY_encapsulate_init(ctx, NULL) ||
        !EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &seclen))
        goto err;
    out = OPENSSL_malloc(outlen);
    secenc = OPENSSL_malloc(seclen);
    secdec = OPENSSL_malloc(seclen);
    if (out == NULL || secenc == NULL || secdec == NULL)
        goto err;
    memset(secenc, 0x11, seclen);
    memset(secdec, 0xff, seclen);
    if (!EVP_PKEY_encapsulate(ctx, out, &outlen, secenc, &seclen))
        goto err;
    if (!EVP_PKEY_decapsulate_init(ctx, NULL) ||
        !EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen))
        goto err;
    if (memcmp(secenc, secdec, seclen) != 0)
        goto err;

    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
                                         &publen))
        goto err;
    pubkey = OPENSSL_malloc(publen);
    if (pubkey == NULL ||
        !EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pubkey,
                                         publen, NULL))
        goto err;
    peer = EVP_PKEY_new_raw_public_key_ex(libctx, kemalg_name, propq, pubkey,
                                          publen);
    if (peer == NULL)
        goto err;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    OPENSSL_free(out);
    out = NULL;
    OPENSSL_free(secenc);
    secenc = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, peer, propq);
    if (ctx == NULL)
        goto err;
    if (!EVP_PKEY_encapsulate_init(ctx, NULL) ||
        !EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &seclen))
        goto err;
    out = OPENSSL_malloc(outlen);
    secenc = OPENSSL_malloc(seclen);
    if (out == NULL || secenc == NULL)
        goto err;
    memset(secenc, 0x11, seclen);
    if (!EVP_PKEY_encapsulate(ctx, out, &outlen, secenc, &seclen))
        goto err;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    OPENSSL_free(secdec);
    secdec = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, propq);
    if (ctx == NULL)
        goto err;
    secdec = OPENSSL_malloc(seclen);
    if (secdec == NULL)
        goto err;
    memset(secdec, 0xff, seclen);
    if (!EVP_PKEY_decapsulate_init(ctx, NULL) ||
        !EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen))
        goto err;
    if (memcmp(secenc, secdec, seclen) != 0)
        goto err;

    testresult = 1;
err:
    EVP_PKEY_free(key);
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(pubkey);
    OPENSSL_free(out);
    OPENSSL_free(secenc);
    OPENSSL_free(secdec);
    return testresult;
}

/*
 * Test hybrid KEMs only. For each enabled hybrid algorithm:
 * - With OQSPROV_PROPQ: expect success.
 * - With NULL propq: expect success (when default provider is available).
 * - With "provider=the-missing-link": expect failure (no such provider).
 */
static int test_oqs_hybrid_kems(const char *kemalg_name) {
    int testresult = 1;

    if (!is_kem_algorithm_hybrid(kemalg_name))
        return 1; /* skip non-hybrid */

    if (!alg_is_enabled(kemalg_name)) {
        fprintf(stderr, "Not testing disabled hybrid KEM %s.\n", kemalg_name);
        return 1;
    }

    if (!OSSL_PROVIDER_available(libctx, "default")) {
        fprintf(stderr,
                "Skipping hybrid KEM test (default provider not loaded): %s.\n",
                kemalg_name);
        return 1;
    }

    /* Must succeed with OQSPROV_PROPQ */
    if (!test_oqs_hybrid_kems_with_propq(kemalg_name, OQSPROV_PROPQ)) {
        fprintf(stderr, "Hybrid KEM failed with OQSPROV_PROPQ: %s\n",
                kemalg_name);
        testresult = 0;
    }

    /* Must succeed with NULL propq (default provider resolves) */
    if (!test_oqs_hybrid_kems_with_propq(kemalg_name, NULL)) {
        fprintf(stderr, "Hybrid KEM failed with NULL propq: %s\n", kemalg_name);
        testresult = 0;
    }

    /* Must fail with non-existent provider (propq is applied) */
    if (test_oqs_hybrid_kems_with_propq(kemalg_name, OQSPROV_PROPQ_MISSING)) {
        fprintf(stderr,
                "Hybrid KEM unexpectedly succeeded with missing provider: %s\n",
                kemalg_name);
        testresult = 0;
    }

    return testresult;
}

#define nelem(a) (sizeof(a) / sizeof((a)[0]))

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0, query_nocache;
    OSSL_PROVIDER *oqsprov = NULL;
    const OSSL_ALGORITHM *kemalgs;

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    load_oqs_provider(libctx, modulename, configfile);

    oqsprov = OSSL_PROVIDER_load(libctx, modulename);

    kemalgs =
        OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);
    if (kemalgs) {
        for (; kemalgs->algorithm_names != NULL; kemalgs++) {
            const char *name = kemalgs->algorithm_names;
            if (is_kem_algorithm_hybrid(name)) {
                if (test_oqs_hybrid_kems(name)) {
                    fprintf(stderr,
                            cGREEN "  Hybrid KEM test succeeded: %s" cNORM "\n",
                            name);
                } else {
                    fprintf(stderr,
                            cRED "  Hybrid KEM test failed: %s" cNORM "\n",
                            name);
                    ERR_print_errors_fp(stderr);
                    errcnt++;
                }
            } else {
                if (test_oqs_kems(name)) {
                    fprintf(stderr,
                            cGREEN "  KEM test succeeded: %s" cNORM "\n", name);
                } else {
                    fprintf(stderr, cRED "  KEM test failed: %s" cNORM "\n",
                            name);
                    ERR_print_errors_fp(stderr);
                    errcnt++;
                }
            }
        }
    }

    OSSL_PROVIDER_unload(oqsprov);
    OSSL_LIB_CTX_free(libctx);

    TEST_ASSERT(errcnt == 0)
    return !test;
}
