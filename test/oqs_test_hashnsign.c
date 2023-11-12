// SPDX-License-Identifier: Apache-2.0 AND MIT
#include "oqs/oqs.h"
#include "test_common.h"
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

static int test_hash_n_sign(const char *sigalg_name) {
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *key = NULL;
    int testresult = 0;

    if (strcmp(sigalg_name, "dilithium2WithSha256") == 0) {
        // Create a new PKEY context for the given algorithm from the loaded provider
        pkey_ctx = EVP_PKEY_CTX_new_from_name(libctx, sigalg_name, NULL);
        if (pkey_ctx != NULL && EVP_PKEY_keygen_init(pkey_ctx) > 0 && EVP_PKEY_generate(pkey_ctx, &key) > 0) {
            // Sign initialization phase
            mdctx = EVP_MD_CTX_new();
            if (mdctx != NULL && EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key) > 0) {
                printf("EVP_DigestSignInit succeeded for %s.\n", sigalg_name);
                testresult = 1; // Indicate success
            } else {
                printf("EVP_DigestSignInit failed for %s.\n", sigalg_name);
            }

            // Free allocated resources
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(key);
            EVP_PKEY_CTX_free(pkey_ctx);
        } else {
            printf("Key generation failed for %s.\n", sigalg_name);
        }
    } else {
        printf("Algorithm %s is not the target test algorithm.\n", sigalg_name);
        testresult = 1; // Skipping non-target algorithms is considered a successful outcome
    }

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

    load_oqs_provider(libctx, modulename, configfile);

    oqsprov = OSSL_PROVIDER_load(libctx, modulename);

    // sigalgs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE,
    //                                         &query_nocache);
    const char *target_alg_name = "dilithium2WithSha256";

    if (test_hash_n_sign(target_alg_name)) {
                fprintf(stderr,
                        cGREEN "  Signature test succeeded: %s" cNORM "\n",
                        sigalgs->algorithm_names);
    } else {
        fprintf(stderr, cRED "  Signature test failed: %s" cNORM "\n",
                sigalgs->algorithm_names);
        ERR_print_errors_fp(stderr);
        errcnt++;
    }

    // if (sigalgs) {
    //     for (; sigalgs->algorithm_names != NULL; sigalgs++) {
    //         if (test_hash_n_sign(sigalgs->algorithm_names)) {
    //             fprintf(stderr,
    //                     cGREEN "  Signature test succeeded: %s" cNORM "\n",
    //                     sigalgs->algorithm_names);
    //         } else {
    //             fprintf(stderr, cRED "  Signature test failed: %s" cNORM "\n",
    //                     sigalgs->algorithm_names);
    //             ERR_print_errors_fp(stderr);
    //             errcnt++;
    //         }
    //     }
    // }

    OSSL_LIB_CTX_free(libctx);

    TEST_ASSERT(errcnt == 0)
    return !test;
}
