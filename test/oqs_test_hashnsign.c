// SPDX-License-Identifier: Apache-2.0 AND MIT
#include "oqs/oqs.h"
#include "test_common.h"
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <string.h>

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *certsdir = NULL;
static char *srpvfile = NULL;
static char *tmpfilename = NULL;

void string_to_lower(char *str)
{
    if (str) {
        for (; *str; ++str)
            *str = tolower((unsigned char)*str);
    }
}

static const EVP_MD *get_digest_for_algorithm(const char *alg_name)
{
    char *lowercase_alg_name = strdup(alg_name);
    if (!lowercase_alg_name) {
        return NULL;
    }

    string_to_lower(lowercase_alg_name);

    const EVP_MD *md = NULL;

    if (strstr(lowercase_alg_name, "sha256"))
        md = EVP_sha256();
    else if (strstr(lowercase_alg_name, "sha384"))
        md = EVP_sha384();
    else if (strstr(lowercase_alg_name, "sha512"))
        md = EVP_sha512();
    else if (strstr(lowercase_alg_name, "sha3-256"))
        md = EVP_sha3_256();
    else if (strstr(lowercase_alg_name, "sha3-384"))
        md = EVP_sha3_384();
    else if (strstr(lowercase_alg_name, "sha3-512"))
        md = EVP_sha3_512();
    else if (strstr(lowercase_alg_name, "shake128"))
        md = EVP_shake128();
    else if (strstr(lowercase_alg_name, "shake256"))
        md = EVP_shake256();

    free(lowercase_alg_name);
    return md;
}

static int test_hash_n_sign(const char *sigalg_name) {
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *key = NULL;
    const char msg[] = "The quick brown fox jumps over the lazy dog";
    unsigned char *sig = NULL;
    size_t siglen;
    int testresult = 0;

    if (!alg_is_enabled(sigalg_name)) {
        printf("Not testing disabled algorithm %s.\n", sigalg_name);
        return 1;
    }

    const EVP_MD *md_type = get_digest_for_algorithm(sigalg_name);
    if (!md_type) {
        printf("Unsupported digest type for algorithm %s.\n Not failing over unsupported hash algs.", sigalg_name);
        return 1;
    }

    pkey_ctx = EVP_PKEY_CTX_new_from_name(libctx, sigalg_name, NULL);
    if (!pkey_ctx) {
        printf("EVP_PKEY_CTX_new_from_name failed for %s.\n", sigalg_name);
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        printf("EVP_PKEY_keygen_init failed for %s.\n", sigalg_name);
        goto cleanup;
    }

    if (EVP_PKEY_generate(pkey_ctx, &key) <= 0) {
        printf("EVP_PKEY_generate failed for %s.\n", sigalg_name);
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("EVP_MD_CTX_new failed for %s.\n", sigalg_name);
        goto cleanup;
    }

    if (EVP_DigestSignInit(mdctx, NULL, md_type, NULL, key) <= 0) {
        printf("EVP_DigestSignInit failed for %s.\n", sigalg_name);
        testresult = 0;
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(mdctx, msg, strlen(msg)) <= 0) {
        printf("EVP_DigestSignUpdate failed for %s.\n", sigalg_name);
        testresult = 0;
        goto cleanup;
    }

    if (EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0) {
        printf("EVP_DigestSignFinal (get length) failed for %s.\n", sigalg_name);
        testresult = 0;
        goto cleanup;
    }

    sig = OPENSSL_malloc(siglen);
    if (sig == NULL) {
        printf("OPENSSL_malloc failed for %s.\n", sigalg_name);
        testresult = 0;
        goto cleanup;
    }

    if (EVP_DigestSignFinal(mdctx, sig, &siglen) <= 0) {
        printf("EVP_DigestSignFinal (get signature) failed for %s.\n", sigalg_name);
        testresult = 0;
        goto cleanup;
    }

    printf("Signature operation successful for %s.\n", sigalg_name);
    testresult = 1;

cleanup:
    if (sig)
        OPENSSL_free(sig);
    if (mdctx)
        EVP_MD_CTX_free(mdctx);
    if (key)
        EVP_PKEY_free(key);
    if (pkey_ctx)
        EVP_PKEY_CTX_free(pkey_ctx);

    return testresult;
}

#define nelem(a) (sizeof(a) / sizeof((a)[0]))

int main(int argc, char *argv[])
{
    size_t i;
    int errcnt = 0, test = 0, query_nocache;
    OSSL_PROVIDER *oqsprov = NULL;
    const OSSL_ALGORITHM *sigalgs;

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    printf("Config file: %s\n", configfile);

    load_oqs_provider(libctx, modulename, configfile);

    oqsprov = OSSL_PROVIDER_load(libctx, modulename);

    sigalgs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE,
                                            &query_nocache);

    if (sigalgs) {
        for (; sigalgs->algorithm_names != NULL; sigalgs++) {
            if (strstr(sigalgs->algorithm_names, "With") != NULL) {
                if (test_hash_n_sign(sigalgs->algorithm_names)) {
                    fprintf(stderr,
                            cGREEN "  Signature test succeeded: %s" cNORM "\n",
                            sigalgs->algorithm_names);
                } else {
                    fprintf(stderr,
                            cRED "  Signature test failed: %s" cNORM "\n",
                            sigalgs->algorithm_names);
                    ERR_print_errors_fp(stderr);
                    errcnt++;
                }
            }
        }
    } else {
        fprintf(stderr, "No signature algorithms available.\n");
    }

    OSSL_LIB_CTX_free(libctx);

    TEST_ASSERT(errcnt == 0)
    return !test;
}
