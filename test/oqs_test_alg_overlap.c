// SPDX-License-Identifier: Apache-2.0 AND MIT
//
// Verifies that oqsprovider does not expose any KEM or signature algorithm
// that OpenSSL's own default provider already implements.
//
// Rationale: starting with OpenSSL 3.5, the default provider natively
// implements a growing set of standardized PQ algorithms (ML-KEM, ML-DSA,
// SLH-DSA and some standardized hybrid KEMs). To avoid clashing (O)ID/name
// registrations and to let OpenSSL's more mature implementations win,
// oqsprovider disables those exact algorithms at runtime (see
// oqsprov/oqsprov.c). This test asserts that property directly instead of
// relying on code inspection: it queries the algorithms registered by the
// oqsprovider and by the default provider and checks that the two sets share
// no (case-insensitive) name or alias.
//
// On OpenSSL < 3.5 the default provider ships no PQ algorithms, so the two
// sets are trivially disjoint and the test still passes.
//
// Usage: oqs_test_alg_overlap <modulename> <config_file>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#include "test_common.h"

#ifdef _WIN32
#define strcasecmp _stricmp
#define strtok_r strtok_s
#endif

/*
 * Returns 1 if \p name (a single algorithm name/alias) appears anywhere in the
 * colon-separated algorithm_names entries of \p algs, matched case
 * insensitively (OpenSSL treats algorithm names as case insensitive). The
 * matching alias is returned via \p match when non-NULL.
 */
static int name_in_algs(const OSSL_ALGORITHM *algs, const char *name,
                        char *match, size_t match_len) {
    char buf[512];

    if (algs == NULL)
        return 0;

    /* Walk each algorithm entry until the NULL-terminated end of the array. */
    for (size_t i = 0; algs[i].algorithm_names != NULL; i++) {
        const OSSL_ALGORITHM *alg = &algs[i];
        char *tok, *save = NULL;

        /*
         * algorithm_names is itself a colon-separated list of aliases for the
         * same algorithm (e.g. "mlkem512:MLKEM512:1.3.6.1.4.1.2.267.7.4.4").
         * Copy it into a scratch buffer (strtok_r mutates its input) and
         * compare each alias against name, case insensitively.
         */
        OPENSSL_strlcpy(buf, alg->algorithm_names, sizeof(buf));
        for (tok = strtok_r(buf, ":", &save); tok != NULL;
             tok = strtok_r(NULL, ":", &save)) {
            if (strcasecmp(tok, name) == 0) {
                /* Report the full alias list of the matching entry, not just
                 * the single alias that matched. */
                if (match != NULL)
                    OPENSSL_strlcpy(match, alg->algorithm_names, match_len);
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Reports every algorithm name/alias registered by oqsprovider (\p oqs_algs)
 * that is also registered by the default provider (\p def_algs). Returns the
 * number of overlapping algorithms found.
 */
static int count_overlap(const OSSL_ALGORITHM *oqs_algs,
                         const OSSL_ALGORITHM *def_algs, const char *optype) {
    char buf[512];
    char match[512];
    int overlap = 0;

    if (oqs_algs == NULL)
        return 0;

    for (size_t i = 0; oqs_algs[i].algorithm_names != NULL; i++) {
        const OSSL_ALGORITHM *oqs_alg = &oqs_algs[i];
        char *tok, *save = NULL;
        int reported = 0;

        OPENSSL_strlcpy(buf, oqs_alg->algorithm_names, sizeof(buf));
        for (tok = strtok_r(buf, ":", &save); tok != NULL && !reported;
             tok = strtok_r(NULL, ":", &save)) {
            if (name_in_algs(def_algs, tok, match, sizeof(match))) {
                fprintf(stderr,
                        cRED
                        "  %s overlap: oqsprovider \"%s\" also provided by "
                        "default as \"%s\" (shared name \"%s\")" cNORM "\n",
                        optype, oqs_alg->algorithm_names, match, tok);
                overlap++;
                reported = 1;
            }
        }
    }
    return overlap;
}

static int test_operation_overlap(OSSL_PROVIDER *oqsprov,
                                  OSSL_PROVIDER *defprov, int operation_id,
                                  const char *optype) {
    const OSSL_ALGORITHM *oqs_algs, *def_algs;
    int nocache = 0;
    int overlap;

    oqs_algs = OSSL_PROVIDER_query_operation(oqsprov, operation_id, &nocache);
    def_algs = OSSL_PROVIDER_query_operation(defprov, operation_id, &nocache);

    overlap = count_overlap(oqs_algs, def_algs, optype);
    if (overlap == 0)
        fprintf(stderr,
                cGREEN "  no %s overlap between oqsprovider and default "
                       "provider" cNORM "\n",
                optype);
    return overlap;
}

int main(int argc, char *argv[]) {
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *oqsprov = NULL, *defprov = NULL;
    int errcnt = 0;

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
        ERR_print_errors_fp(stderr);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }

    defprov = load_default_provider(libctx);
    if (defprov == NULL) {
        fprintf(stderr, "OSSL_PROVIDER_load(default) failed\n");
        ERR_print_errors_fp(stderr);
        OSSL_PROVIDER_unload(oqsprov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }

    errcnt += test_operation_overlap(oqsprov, defprov, OSSL_OP_KEM, "KEM");
    errcnt += test_operation_overlap(oqsprov, defprov, OSSL_OP_SIGNATURE,
                                     "signature");

    if (errcnt == 0)
        fprintf(stderr, cGREEN "OQS algorithm overlap test finished without "
                               "failures" cNORM "\n");
    else
        fprintf(stderr,
                cRED "OQS algorithm overlap test found %d overlapping "
                     "algorithm(s)" cNORM "\n",
                errcnt);

    OSSL_PROVIDER_unload(defprov);
    OSSL_PROVIDER_unload(oqsprov);
    OSSL_LIB_CTX_free(libctx);

    return errcnt == 0 ? 0 : 1;
}
