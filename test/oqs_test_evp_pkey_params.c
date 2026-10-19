// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oqs_prov.h"
#include "test_common.h"

/* [mb-nohybrids] KeyPair + hybrid param-split test helpers removed */

/** \brief Initializes an OpenSSL top-level context.
 *
 * \returns The top-level context, or `NULL` if an error occurred. */
static OSSL_LIB_CTX *init_openssl(void) {
    OSSL_LIB_CTX *ctx;

    if (!(ctx = OSSL_LIB_CTX_new())) {
        fputs(cRED "failed to initialize a new `OSSL_LIB_CTX` " cNORM "\n",
              stderr);
    }

    return ctx;
}

/* [mb-nohybrids] hybrid key-params tests (test_algorithm,
 * test_pubkey_only_hybrid_get_params + helpers) removed */

/** \brief Tests that KEM decapsulation fails cleanly after the private key has
 * been dropped via OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.
 *
 * Regression test for GHSA-g63q-c378-wphj (canonical reference for this fix):
 * dropping the private key via the encoded-public-key param left comp_privkey[]
 * dangling into the freed buffer, which KEM decaps then read. Post-fix, decaps
 * must fail rather than read freed memory (heap-use-after-free under
 * AddressSanitizer on a vulnerable build).
 *
 * Uses only public OpenSSL API and self-selects KEMs (signatures cannot
 * encapsulate), so it is safe to call for every keymgmt algorithm.
 *
 * \param libctx Top-level OpenSSL context.
 * \param algname Algorithm name.
 *
 * \returns 0 on success (including for non-KEM algorithms, which are skipped).
 */
static int test_decaps_after_set_encoded_public_key(OSSL_LIB_CTX *libctx,
                                                    const char *algname) {
    EVP_PKEY_CTX *ctx = NULL, *encctx = NULL, *decctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *encpub = NULL, *ct = NULL, *secret = NULL;
    size_t encpub_len = 0, ctlen = 0, secretlen = 0;
    int ret = -1;

    /* Generate a full keypair. */
    ctx = EVP_PKEY_CTX_new_from_name(libctx, algname, OQSPROV_PROPQ);
    if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 ||
        EVP_PKEY_generate(ctx, &key) != 1) {
        fprintf(stderr,
                cRED "  decaps-after-set-encoded-pubkey: keygen failed "
                     "for %s" cNORM "\n",
                algname);
        goto err;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Only KEM algorithms support encapsulation; signatures are skipped. */
    encctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, OQSPROV_PROPQ);
    if (!encctx) {
        goto err;
    }
    if (EVP_PKEY_encapsulate_init(encctx, NULL) <= 0) {
        ERR_clear_error();
        ret = 0; /* not a KEM: nothing to exercise here */
        goto err;
    }

    /* Produce a valid ciphertext from the public key (needs no private key). */
    if (EVP_PKEY_encapsulate(encctx, NULL, &ctlen, NULL, &secretlen) != 1) {
        goto err;
    }
    ct = malloc(ctlen);
    secret = malloc(secretlen);
    if (!ct || !secret) {
        fprintf(stderr, cRED "  decaps-after-set-encoded-pubkey: malloc "
                             "failed" cNORM "\n");
        goto err;
    }
    if (EVP_PKEY_encapsulate(encctx, ct, &ctlen, secret, &secretlen) != 1) {
        goto err;
    }

    /* Read the encoded public key back to feed it in at the expected size. */
    encpub_len = EVP_PKEY_get1_encoded_public_key(key, &encpub);
    if (encpub_len == 0 || encpub == NULL) {
        fprintf(stderr,
                cRED "  decaps-after-set-encoded-pubkey: get encoded pubkey "
                     "failed for %s" cNORM "\n",
                algname);
        goto err;
    }

    /* Trigger: setting the encoded public key frees the private key. */
    if (EVP_PKEY_set1_encoded_public_key(key, encpub, encpub_len) != 1) {
        fprintf(stderr,
                cRED "  decaps-after-set-encoded-pubkey: set encoded pubkey "
                     "failed for %s" cNORM "\n",
                algname);
        goto err;
    }

    /* Must fail cleanly now; a vulnerable build reads the freed privkey here.
     */
    decctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, OQSPROV_PROPQ);
    if (!decctx || EVP_PKEY_decapsulate_init(decctx, NULL) != 1) {
        goto err;
    }
    memset(secret, 0, secretlen);
    if (EVP_PKEY_decapsulate(decctx, secret, &secretlen, ct, ctlen) > 0) {
        fprintf(stderr,
                cRED "  decaps-after-set-encoded-pubkey: decapsulation "
                     "unexpectedly succeeded without a private key "
                     "for %s" cNORM "\n",
                algname);
        goto err;
    }
    ERR_clear_error(); /* the expected decapsulation failure raised errors */
    ret = 0;

err:
    free(encpub);
    free(ct);
    free(secret);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(encctx);
    EVP_PKEY_CTX_free(decctx);
    return ret;
}

/** \brief Tests the export/import capacity of an algorithm.
 *
 * \param libctx Top-level OpenSSL context.
 * \param algname Algorithm name.
 *
 * \returns 0 on success. */
static int test_export_data(OSSL_LIB_CTX *libctx, const char *algname) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL, *copy = NULL;
    OSSL_PARAM *todata_params = NULL;
    int testresult = 1;

    testresult &= (ctx = EVP_PKEY_CTX_new_from_name(libctx, algname,
                                                    OQSPROV_PROPQ)) != NULL &&
                  EVP_PKEY_keygen_init(ctx) && EVP_PKEY_generate(ctx, &key);

    if (!testresult)
        goto err;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    testresult &=
        EVP_PKEY_todata(key, EVP_PKEY_KEYPAIR, &todata_params) &&
        (ctx = EVP_PKEY_CTX_new_from_name(libctx, algname, OQSPROV_PROPQ)) !=
            NULL &&
        EVP_PKEY_fromdata_init(ctx) &&
        EVP_PKEY_fromdata(ctx, &copy, EVP_PKEY_KEYPAIR, todata_params) &&
        EVP_PKEY_eq(key, copy);

err:
    EVP_PKEY_free(key);
    EVP_PKEY_free(copy);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(todata_params);
    return !testresult;
}

int main(int argc, char **argv) {
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *default_provider;
    OSSL_PROVIDER *oqs_provider;
    const char *modulename;
    const char *configfile;
    const OSSL_ALGORITHM *algs;
    int query_nocache;
    int errcnt;
    int test = 0;

    if (!(libctx = init_openssl())) {
        goto end;
    }

    if (!(default_provider = load_default_provider(libctx))) {
        goto free_libctx;
    }

    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    load_oqs_provider(libctx, modulename, configfile);
    if (!(oqs_provider = OSSL_PROVIDER_load(libctx, modulename))) {
        fputs(cRED "  `oqs_provider` is NULL " cNORM "\n", stderr);
        goto unload_default_provider;
    }

    errcnt = 0;
    algs = OSSL_PROVIDER_query_operation(oqs_provider, OSSL_OP_KEYMGMT,
                                         &query_nocache);
    if (!algs) {
        fprintf(stderr, cRED "  No algorithms found" cNORM "\n");
        ERR_print_errors_fp(stderr);
        ++errcnt;
        goto unload_oqs_provider;
    }

    for (; algs->algorithm_names != NULL; ++algs) {
        test = test_export_data(libctx, algs->algorithm_names);
        /* [mb-nohybrids] hybrid-only param tests removed */
        /* KEMs only (function skips signatures) */
        test = test || test_decaps_after_set_encoded_public_key(
                           libctx, algs->algorithm_names);
        if (test) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr,
                    cRED "EVP_PKEY params test failed for %s " cNORM "\n",
                    algs->algorithm_names);
            ++errcnt;
        } else {
            fprintf(stderr,
                    cGREEN "EVP_PKEY params test %s succeeded" cNORM "\n",
                    algs->algorithm_names);
        }
    }

unload_oqs_provider:
    OSSL_PROVIDER_unload(oqs_provider);

unload_default_provider:
    OSSL_PROVIDER_unload(default_provider);

free_libctx:
    OSSL_LIB_CTX_free(libctx);

end:
    TEST_ASSERT(errcnt == 0)
    return !test;
}
