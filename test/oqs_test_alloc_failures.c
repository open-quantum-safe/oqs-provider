// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <string.h>

#include "oqs/oqs.h"
#include "test_common.h"
#include "tlstest_helpers.h"

// If this is updated, update the reference in CMakeLists.txt
#define EXIT_SKIP 77

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;

// The file containing the mallocs we want to fail
static const char *target_file = "";

// We want the nth malloc to fail (0-indexed)
static long fail_nth = -1;
// Used to count allocations
static long hits = 0;

void *test_malloc(size_t num, const char *file, int line) {
    if (file && strstr(file, target_file) != NULL) {
        if (hits++ == fail_nth) {
            fprintf(stderr, cGREEN "   Injecting malloc failure at %s:%d\n",
                    file, line);
            return NULL;
        }
    }
    return malloc(num);
}

void *test_realloc(void *addr, size_t num, const char *file, int line) {
    return realloc(addr, num);
}

void test_free(void *addr, const char *file, int line) { free(addr); }

int test_alloc_failures(const char *algname) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    int testresult = 1;

    if (!alg_is_enabled(algname)) {
        fprintf(stderr, "Not testing disabled algorithm %s.\n", algname);
        return 1;
    }

    if (OSSL_PROVIDER_available(libctx, "default")) {
        testresult &= (ctx = EVP_PKEY_CTX_new_from_name(
                           libctx, algname, OQSPROV_PROPQ)) != NULL &&
                      EVP_PKEY_keygen_init(ctx) && EVP_PKEY_generate(ctx, &key);
    }

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return testresult;
}

// This test is meant to crash with either a NULL pointer access or
// some address sanitizer error if malloc failures aren't handled
int main(int argc, char *argv[]) {
    int query_nocache;
    OSSL_PROVIDER *oqsprov = NULL;
    const OSSL_ALGORITHM *algs;
    int work_done = 0;

    T(CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free) == 1);

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    load_oqs_provider(libctx, modulename, configfile);

    // Test the hybrid signature functions
    oqsprov = OSSL_PROVIDER_load(libctx, modulename);
    algs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE,
                                         &query_nocache);

    // We only want to insert malloc failures in oqsprov_keys.c
    target_file = "oqsprov_keys.c";

    for (; algs && algs->algorithm_names != NULL; ++algs) {
        const char *name = algs->algorithm_names;
        if (!is_signature_algorithm_hybrid(name))
            continue;

        fprintf(stderr, cGREEN "  Testing signature algorithm %s\n" cNORM,
                name);
        // This counts the number of allocations in the target file
        hits = 0;
        fail_nth = -1;
        test_alloc_failures(name);
        long allocs = hits;
        if (allocs == 0)
            continue;

        work_done = 1;

        for (fail_nth = 0; fail_nth < allocs; ++fail_nth) {
            hits = 0;
            test_alloc_failures(name);
        }
    }

    // Make sure we don't fail any mallocs in OSSL_PROVIDER_query_operation
    fail_nth = -1;

    // Now test the hybrid kem functions
    algs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);
    for (; algs && algs->algorithm_names != NULL; ++algs) {
        const char *name = algs->algorithm_names;
        if (!is_kem_algorithm_hybrid(name))
            continue;

        fprintf(stderr, cGREEN "  Testing kem algorithm %s\n" cNORM, name);
        // This counts the number of allocations in the target file
        hits = 0;
        fail_nth = -1;
        test_alloc_failures(name);
        long allocs = hits;
        if (allocs == 0)
            continue;

        work_done = 1;

        for (fail_nth = 0; fail_nth < allocs; ++fail_nth) {
            hits = 0;
            test_alloc_failures(name);
        }
    }

    if (!work_done)
        fprintf(stderr,
                cYELLOW "  No allocations intercepted in %s.\n"
                        "  Nothing can be tested, skipping.\n" cNORM,
                target_file);

    OSSL_PROVIDER_unload(oqsprov);
    OSSL_LIB_CTX_free(libctx);
    return work_done ? EXIT_SUCCESS : EXIT_SKIP;
}
