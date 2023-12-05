// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <pthread.h>

#include <openssl/crypto.h>
#include <openssl/provider.h>

#include "test_common.h"

static const size_t N_THREADS = 32;

static const char *kModuleName = NULL;
static const char *kConfigFile = NULL;

/** \brief Loads the oqs-provider in an `OSSL_LIB_CTX` object. */
static int load_oqs_provider_thread(OSSL_LIB_CTX *lib_ctx)
{
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *oqs_provider = NULL;
    int ret = -1;

#ifdef OQS_PROVIDER_STATIC

    if ((default_provider = OSSL_PROVIDER_load(lib_ctx, "default")) == NULL) {
        goto end;
    }
    if (OSSL_PROVIDER_add_builtin(lib_ctx, "oqsprovider",
                                  OQS_PROVIDER_ENTRYPOINT_NAME)
        != 1) {
        putchar('-');
        goto unload_default_provider;
    }
    if ((oqs_provider = OSSL_PROVIDER_load(lib_ctx, "oqsprovider")) == NULL) {
        putchar('/');
        goto unload_default_provider;
    }
    ret = 0;
    OSS_PROVIDER_unload(oqs_provider);

#else

    if (OSSL_LIB_CTX_load_config(lib_ctx, kConfigFile) == 1
        && OSSL_PROVIDER_available(lib_ctx, kModuleName)) {
        putchar('>');
        ret = 0;
    }
    goto end;

#endif // ifdef OQS_PROVIDER_STATIC

unload_default_provider:
    OSSL_PROVIDER_unload(default_provider);

end:
    return ret;
}

/** \brief Creates an OSSL_LIB_CTX object and loads oqs-provider. */
static void *thread_create_ossl_lib_ctx(void *arg)
{
    OSSL_LIB_CTX *lib_ctx = NULL;
    int ret = -1;

    (void)arg;

    if ((lib_ctx = OSSL_LIB_CTX_new()) == NULL) {
        goto end;
    }
    ret = load_oqs_provider_thread(lib_ctx);
    OSSL_LIB_CTX_free(lib_ctx);

end:
    return (void *)(size_t)ret;
}

int main(int argc, char **argv)
{
    size_t i;
    pthread_t threads[N_THREADS];
    void *result;
    int ret = 0;

    T(argc == 3);

    kModuleName = argv[1];
    kConfigFile = argv[2];

    for (i = 0; i < N_THREADS; ++i) {
        pthread_create(threads + i, NULL, thread_create_ossl_lib_ctx, NULL);
    }

    for (i = 0; i < N_THREADS; ++i) {
        result = NULL;
        pthread_join(threads[i], &result);
        ret |= (int)(size_t)result;
    }

    return ret;
}
