// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <pthread.h>

#include "test_common.h"

#define NUM_THREADS 16

static char *modulename = NULL;
static char *configfile = NULL;

struct thread_ctx {
    OSSL_LIB_CTX *libctx;
    int algcount;
};

/** \brief Loads the oqs-provider and counts the algorithms it offers.
 *
 * \param libctx Library context to load the provider into.
 *
 * \return The number of KEM and signature algorithms, or -1 on error. */
static int count_oqs_provider_algs(OSSL_LIB_CTX *libctx) {
    const OSSL_ALGORITHM *algs;
    OSSL_PROVIDER *oqsprov;
    int algcount = 0, query_nocache;

    load_oqs_provider(libctx, modulename, configfile);
    if ((oqsprov = OSSL_PROVIDER_load(libctx, modulename)) == NULL)
        return -1;

    algs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);
    for (; algs != NULL && algs->algorithm_names != NULL; algs++)
        algcount++;

    algs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE,
                                         &query_nocache);
    for (; algs != NULL && algs->algorithm_names != NULL; algs++)
        algcount++;

    return algcount;
}

static void *load_oqs_provider_thread(void *arg) {
    struct thread_ctx *tctx = arg;

    T((tctx->libctx = OSSL_LIB_CTX_new()) != NULL);
    tctx->algcount = count_oqs_provider_algs(tctx->libctx);
    return NULL;
}

int main(int argc, char *argv[]) {
    struct thread_ctx tctx[NUM_THREADS] = {0};
    pthread_t threads[NUM_THREADS];
    OSSL_LIB_CTX *libctx = NULL;
    int i, algcount, errcnt = 0, test = 0;

    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    // reference: registration in a process not yet using the provider
    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T((algcount = count_oqs_provider_algs(libctx)) > 0);
    OSSL_LIB_CTX_free(libctx);

    for (i = 0; i < NUM_THREADS; i++)
        T(pthread_create(threads + i, NULL, load_oqs_provider_thread,
                         tctx + i) == 0);

    for (i = 0; i < NUM_THREADS; i++)
        T(pthread_join(threads[i], NULL) == 0);

    for (i = 0; i < NUM_THREADS; i++) {
        if (tctx[i].algcount != algcount) {
            fprintf(stderr,
                    cRED " thread %d: %d of %d algorithms available" cNORM "\n",
                    i, tctx[i].algcount, algcount);
            errcnt++;
        }
        OSSL_LIB_CTX_free(tctx[i].libctx);
    }

    TEST_ASSERT(errcnt == 0)
    return !test;
}
