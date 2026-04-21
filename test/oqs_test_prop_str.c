// SPDX-License-Identifier: Apache-2.0 AND MIT
//
// Verifies the OQS keymgmt stores the property query on KEM keys by
// reading OSSL_PKEY_PARAM_PROPERTIES via EVP.
//
// Expected property string: OQS_TST_PROPQ (provider=default,
// provider=oqsprovider, fips=no). Override at compile time with
// -DOQS_TST_PROPQ=...
//
// Usage: oqs_test_prop_str <modulename> <config_file>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#include "test_common.h"

#ifndef OQS_TST_PROPQ
#define OQS_TST_PROPQ "provider=default,provider=oqsprovider,fips=no"
#endif

#ifdef _MSC_VER
#define strtok_r strtok_s
#endif

static int test_propq_on_pkey(OSSL_LIB_CTX *libctx, const char *algname,
                              int expect_null_propq) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    char buf[512];
    size_t got_len = 0;
    int ok = 0;

    /*
     * The third argument only affects EVP_KEYMGMT_fetch; OpenSSL does not pass
     * it into keygen.  To record the query on the key, set
     * OSSL_PKEY_PARAM_PROPERTIES on the genctx after EVP_PKEY_keygen_init().
     */
    ctx = EVP_PKEY_CTX_new_from_name(libctx, algname, OQS_TST_PROPQ);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name(%s) failed\n", algname);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed for %s\n", algname);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (!expect_null_propq) {
        OSSL_PARAM props[2];

        props[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PROPERTIES,
                                                    (char *)OQS_TST_PROPQ, 0);
        props[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(ctx, props) <= 0) {
            fprintf(stderr,
                    "EVP_PKEY_CTX_set_params(PROPERTIES) failed for %s\n",
                    algname);
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen failed for %s\n", algname);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_PROPERTIES, buf,
                                        sizeof(buf), &got_len)) {
        fprintf(stderr,
                "EVP_PKEY_get_utf8_string_param(PROPERTIES) failed "
                "for %s\n",
                algname);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        return 0;
    }

    if (expect_null_propq) {
        if (got_len != 0) {
            fprintf(stderr,
                    "expected empty PROPERTIES on key for %s, got len %zu\n",
                    algname, got_len);
            ok = 0;
        } else {
            ok = 1;
        }
    } else {
        if (got_len != strlen(OQS_TST_PROPQ) ||
            strcmp(buf, OQS_TST_PROPQ) != 0) {
            fprintf(stderr,
                    "PROPERTIES mismatch for %s: got \"%s\" (len %zu), "
                    "expected \"%s\" (OQS_TST_PROPQ)\n",
                    algname, buf, got_len, OQS_TST_PROPQ);
            ok = 0;
        } else {
            ok = 1;
        }
    }

    EVP_PKEY_free(pkey);
    return ok;
}

int main(int argc, char *argv[]) {
    const OSSL_ALGORITHM *algs;
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *oqsprov = NULL;
    int query_nocache = 0;
    int errcnt = 0;
    int kem_runs = 0;
    int sig_runs = 0;
    int ret;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <modulename> <config_file>\n", argv[0]);
        return 1;
    }

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new failed\n");
        return 1;
    }

    load_oqs_provider(libctx, argv[1], argv[2]);

    oqsprov = OSSL_PROVIDER_load(libctx, argv[1]);
    if (oqsprov == NULL) {
        fprintf(stderr, "OSSL_PROVIDER_load(%s) failed\n", argv[1]);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }

    algs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);
    if (algs) {
        for (; algs->algorithm_names != NULL; algs++) {
            char buf[256];
            char *saveptr = NULL;
            char *tok;

            OPENSSL_strlcpy(buf, algs->algorithm_names, sizeof(buf));
            for (tok = strtok_r(buf, ",", &saveptr); tok != NULL;
                 tok = strtok_r(NULL, ",", &saveptr)) {
                while (*tok == ' ')
                    tok++;

                if (!alg_is_enabled(tok)) {
                    fprintf(stderr, "Not testing disabled KEM %s.\n", tok);
                    continue;
                }

                fprintf(stderr, "testing KEM \"%s\" (PROPERTIES / propq)\n",
                        tok);

                {
                    int ok1 = test_propq_on_pkey(libctx, tok, 0);
                    int ok2 = test_propq_on_pkey(libctx, tok, 1);

                    if (!ok1)
                        errcnt++;
                    if (!ok2)
                        errcnt++;
                    kem_runs++;
                    if (ok1 && ok2) {
                        fprintf(stderr,
                                cGREEN "  KEM PROPERTIES checks "
                                       "passed: %s" cNORM "\n",
                                tok);
                    } else {
                        fprintf(stderr,
                                cRED "  KEM PROPERTIES checks failed: "
                                     "%s" cNORM "\n",
                                tok);
                    }
                }
            }
        }
    }

    if (kem_runs == 0) {
        fprintf(stderr, "warning: no enabled KEM was exercised "
                        "(none registered or all skipped)\n");
    }

    algs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE,
                                         &query_nocache);
    if (algs) {
        for (; algs->algorithm_names != NULL; algs++) {
            char buf[256];
            char *saveptr = NULL;
            char *tok;

            OPENSSL_strlcpy(buf, algs->algorithm_names, sizeof(buf));
            for (tok = strtok_r(buf, ",", &saveptr); tok != NULL;
                 tok = strtok_r(NULL, ",", &saveptr)) {
                while (*tok == ' ')
                    tok++;

                /* User asked for PQ signatures; skip hybrids here. */
                if (is_signature_algorithm_hybrid(tok))
                    continue;

                if (!alg_is_enabled(tok)) {
                    fprintf(stderr, "Not testing disabled PQ signature %s.\n",
                            tok);
                    continue;
                }

                fprintf(stderr,
                        "testing PQ signature \"%s\" (PROPERTIES / propq)\n",
                        tok);

                {
                    int ok1 = test_propq_on_pkey(libctx, tok, 0);
                    int ok2 = test_propq_on_pkey(libctx, tok, 1);

                    if (!ok1)
                        errcnt++;
                    if (!ok2)
                        errcnt++;
                    sig_runs++;
                    if (ok1 && ok2) {
                        fprintf(stderr,
                                cGREEN "  PQ signature PROPERTIES checks "
                                       "passed: %s" cNORM "\n",
                                tok);
                    } else {
                        fprintf(stderr,
                                cRED "  PQ signature PROPERTIES checks failed: "
                                     "%s" cNORM "\n",
                                tok);
                    }
                }
            }
        }
    }

    if (sig_runs == 0) {
        fprintf(stderr, "warning: no enabled PQ signature was exercised "
                        "(none registered or all skipped)\n");
    }

    ret = errcnt != 0 ? 1 : 0;
    if (ret == 0) {
        fprintf(stderr,
                cGREEN "OQS KEM/PQ-signature PROPERTIES (propq) EVP tests "
                       "finished "
                       "without failures" cNORM "\n");
    }

    OSSL_PROVIDER_unload(oqsprov);
    OSSL_LIB_CTX_free(libctx);
    return ret;
}
