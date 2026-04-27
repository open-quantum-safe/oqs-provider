// SPDX-License-Identifier: Apache-2.0 AND MIT
//
// Verifies the OQS keymgmt stores the property query on KEM and signature
// keys by reading OSSL_PKEY_PARAM_PROPERTIES via EVP.
//
// Expected property strings: OQS_TST_PROPQ (default:
// provider=default,provider=oqsprovider,fips=no) and OQS_TST_PROPQ_2
// (default: provider=oqsprovider). Override at compile time with
// -DOQS_TST_PROPQ=... / -DOQS_TST_PROPQ_2=...
//
// The narrow propq (OQS_TST_PROPQ_2) case: non-hybrid KEMs and all signature
// algorithms should pass both sub-tests. Hybrid KEMs should not pass both: with
// only "provider=oqsprovider" they typically fail (e.g. keygen) or otherwise do
// not complete both checks successfully.
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

#ifndef OQS_TST_PROPQ_2
#define OQS_TST_PROPQ_2 "provider=oqsprovider"
#endif

static int test_propq_on_pkey_ex(OSSL_LIB_CTX *libctx, const char *algname,
                                 int expect_null_propq, const char *propq) {
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
    ctx = EVP_PKEY_CTX_new_from_name(libctx, algname, propq);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name(%s) failed\n", algname);
        goto err;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed for %s\n", algname);
        goto err;
    }
    if (!expect_null_propq) {
        OSSL_PARAM props[2];

        props[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PROPERTIES,
                                                    (char *)propq, 0);
        props[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(ctx, props) <= 0) {
            fprintf(stderr,
                    "EVP_PKEY_CTX_set_params(PROPERTIES) failed for %s\n",
                    algname);
            goto err;
        }
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen failed for %s\n", algname);
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto err;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_PROPERTIES, buf,
                                        sizeof(buf), &got_len)) {
        fprintf(stderr,
                "EVP_PKEY_get_utf8_string_param(PROPERTIES) failed "
                "for %s\n",
                algname);
        goto err;
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
        if (got_len != strlen(propq) || strcmp(buf, propq) != 0) {
            fprintf(stderr,
                    "PROPERTIES mismatch for %s: got \"%s\" (len %zu), "
                    "expected \"%s\" (propq)\n",
                    algname, buf, got_len, propq);
            ok = 0;
        } else {
            ok = 1;
        }
    }
    goto cleanup;

err:
    ERR_print_errors_fp(stderr);
cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* KEM: non-hybrids must get ok1&&ok2; hybrid KEMs must not get both. */
/* SIG: every enabled algorithm must get ok1&&ok2. */
static void acc_propq2_narrow(int ok1, int ok2, int is_kem, int is_kem_hybrid,
                              const char *label, const char *algname,
                              int *errcnt, int *runs) {
    int pass;
    if (is_kem)
        pass = is_kem_hybrid ? !(ok1 && ok2) : (ok1 && ok2);
    else
        pass = (ok1 && ok2);

    if (pass) {
        fprintf(
            stderr,
            cGREEN
            "  %s (OQS_TST_PROPQ_2) kem_hybrid=%d: passed: %s (got %d,%d)" cNORM
            "\n",
            label, is_kem ? is_kem_hybrid : 0, algname, ok1, ok2);
    } else {
        fprintf(
            stderr,
            cRED
            "  %s (OQS_TST_PROPQ_2) kem_hybrid=%d: failed: %s (got %d,%d)" cNORM
            "\n",
            label, is_kem ? is_kem_hybrid : 0, algname, ok1, ok2);
        (*errcnt)++;
    }
    (*runs)++;
}

int main(int argc, char *argv[]) {
    const OSSL_ALGORITHM *algs;
    const OSSL_ALGORITHM *kem_algs;
    const OSSL_ALGORITHM *sig_algs;
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *oqsprov = NULL;
    int query_nocache = 0;
    int errcnt = 0;
    int kem_runs = 0;
    int sig_runs = 0;
    int kem2_runs = 0;
    int sig2_runs = 0;
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

    kem_algs =
        OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);
    if (kem_algs) {
        for (algs = kem_algs; algs->algorithm_names != NULL; algs++) {
            const char *algname = algs->algorithm_names;

            if (!alg_is_enabled(algname)) {
                fprintf(stderr, "Skip disabled KEM %s.\n", algname);
                continue;
            }

            fprintf(stderr, "testing KEM \"%s\" (PROPERTIES / propq)\n",
                    algname);

            {
                int ok1 =
                    test_propq_on_pkey_ex(libctx, algname, 0, OQS_TST_PROPQ);
                int ok2 =
                    test_propq_on_pkey_ex(libctx, algname, 1, OQS_TST_PROPQ);

                if (!ok1)
                    errcnt++;
                if (!ok2)
                    errcnt++;
                kem_runs++;
                if (ok1 && ok2) {
                    fprintf(stderr,
                            cGREEN "  KEM PROPERTIES checks "
                                   "passed: %s" cNORM "\n",
                            algname);
                } else {
                    fprintf(stderr,
                            cRED "  KEM PROPERTIES checks failed: "
                                 "%s" cNORM "\n",
                            algname);
                }
            }
        }
    }

    if (kem_runs == 0) {
        fprintf(stderr, "No KEM algs tested for OQS_TST_PROPQ.\n");
    }

    if (kem_algs) {
        for (algs = kem_algs; algs->algorithm_names != NULL; algs++) {
            const char *algname = algs->algorithm_names;
            int hybrid = is_kem_algorithm_hybrid(algname);

            if (!alg_is_enabled(algname)) {
                fprintf(stderr, "Skip disabled KEM %s (OQS_TST_PROPQ_2).\n",
                        algname);
                continue;
            }

            fprintf(stderr,
                    "testing KEM \"%s\" (OQS_TST_PROPQ_2, hybrid check)\n",
                    algname);

            {
                int ok1 =
                    test_propq_on_pkey_ex(libctx, algname, 0, OQS_TST_PROPQ_2);
                int ok2 =
                    test_propq_on_pkey_ex(libctx, algname, 1, OQS_TST_PROPQ_2);

                acc_propq2_narrow(ok1, ok2, 1, hybrid, "KEM", algname, &errcnt,
                                  &kem2_runs);
            }
        }
    }

    if (kem2_runs == 0) {
        fprintf(stderr, "No KEM algs tested for OQS_TST_PROPQ_2.\n");
    }

    sig_algs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE,
                                             &query_nocache);
    if (sig_algs) {
        for (algs = sig_algs; algs->algorithm_names != NULL; algs++) {
            const char *algname = algs->algorithm_names;

            /* User asked for PQ signatures; skip hybrids here. */
            if (is_signature_algorithm_hybrid(algname))
                continue;

            if (!alg_is_enabled(algname)) {
                fprintf(stderr, "Skip disabled PQ signature %s.\n", algname);
                continue;
            }

            fprintf(stderr,
                    "testing PQ signature \"%s\" (PROPERTIES / propq)\n",
                    algname);

            {
                int ok1 =
                    test_propq_on_pkey_ex(libctx, algname, 0, OQS_TST_PROPQ);
                int ok2 =
                    test_propq_on_pkey_ex(libctx, algname, 1, OQS_TST_PROPQ);

                if (!ok1)
                    errcnt++;
                if (!ok2)
                    errcnt++;
                sig_runs++;
                if (ok1 && ok2) {
                    fprintf(stderr,
                            cGREEN "  PQ signature PROPERTIES checks "
                                   "passed: %s" cNORM "\n",
                            algname);
                } else {
                    fprintf(stderr,
                            cRED "  PQ signature PROPERTIES checks failed: "
                                 "%s" cNORM "\n",
                            algname);
                }
            }
        }
    }

    if (sig_runs == 0) {
        fprintf(stderr, "No PQ signature algs tested for OQS_TST_PROPQ.\n");
    }

    if (sig_algs) {
        for (algs = sig_algs; algs->algorithm_names != NULL; algs++) {
            const char *algname = algs->algorithm_names;

            if (!alg_is_enabled(algname)) {
                fprintf(stderr,
                        "Skip disabled signature %s (OQS_TST_PROPQ_2).\n",
                        algname);
                continue;
            }

            fprintf(stderr, "testing signature \"%s\" (OQS_TST_PROPQ_2)\n",
                    algname);

            {
                int ok1 =
                    test_propq_on_pkey_ex(libctx, algname, 0, OQS_TST_PROPQ_2);
                int ok2 =
                    test_propq_on_pkey_ex(libctx, algname, 1, OQS_TST_PROPQ_2);

                acc_propq2_narrow(ok1, ok2, 0, 0, "SIG", algname, &errcnt,
                                  &sig2_runs);
            }
        }
    }

    if (sig2_runs == 0) {
        fprintf(stderr, "No PQ signature algs tested for OQS_TST_PROPQ_2.\n");
    }

    ret = errcnt != 0 ? 1 : 0;
    if (ret == 0) {
        fprintf(stderr,
                cGREEN "OQS KEM/signature PROPERTIES (propq / OQS_TST_PROPQ_2) "
                       "EVP tests finished without failures" cNORM "\n");
    }

    OSSL_PROVIDER_unload(oqsprov);
    OSSL_LIB_CTX_free(libctx);
    return ret;
}
