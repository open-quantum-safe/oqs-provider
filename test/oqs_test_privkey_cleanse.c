// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdlib.h>
#include <string.h>

#include "oqs/oqs.h"
#include "test_common.h"

// Every allocation carries its size in front, so that a free can look inside
#define HDR 16
// Number of private key bytes searched for in freed blocks
#define WINDOW 24

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;

static unsigned char window[WINDOW];
static int armed = 0;
static int leaks = 0;

static int contains_window(const unsigned char *p, size_t num) {
    size_t i;

    for (i = 0; i + WINDOW <= num; i++)
        if (memcmp(p + i, window, WINDOW) == 0)
            return 1;
    return 0;
}

static void check_freed(const unsigned char *p, const char *file, int line) {
    size_t num;

    memcpy(&num, p - HDR, sizeof(num));
    if (armed && contains_window(p, num)) {
        fprintf(stderr,
                cRED "    %zu-byte block freed at %s:%d still holds private "
                     "key bytes\n" cNORM,
                num, file, line);
        leaks++;
    }
}

static void *test_malloc(size_t num, const char *file, int line) {
    unsigned char *p = malloc(num + HDR);

    if (p == NULL)
        return NULL;
    memcpy(p, &num, sizeof(num));
    return p + HDR;
}

static void test_free(void *addr, const char *file, int line) {
    if (addr == NULL)
        return;
    check_freed(addr, file, line);
    free((unsigned char *)addr - HDR);
}

static void *test_realloc(void *addr, size_t num, const char *file, int line) {
    unsigned char *p;
    size_t old;

    if (addr == NULL)
        return test_malloc(num, file, line);
    if (num == 0) {
        test_free(addr, file, line);
        return NULL;
    }
    if ((p = test_malloc(num, file, line)) == NULL)
        return NULL;
    memcpy(&old, (unsigned char *)addr - HDR, sizeof(old));
    memcpy(p, addr, old < num ? old : num);
    test_free(addr, file, line);
    return p;
}

// Picks WINDOW bytes of the private key that do not occur in the public key
// and are not padding.
static int pick_window(EVP_PKEY *key) {
    unsigned char *priv = NULL, *pub = NULL;
    size_t privlen = 0, publen = 0, off, i;
    int found = 0;

    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0,
                                         &privlen) ||
        !EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
                                         &publen))
        return 0;
    if ((priv = OPENSSL_malloc(privlen)) == NULL ||
        (pub = OPENSSL_malloc(publen)) == NULL ||
        !EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY, priv,
                                         privlen, &privlen) ||
        !EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pub,
                                         publen, &publen))
        goto end;

    for (off = 0; !found && off + WINDOW <= privlen; off += WINDOW) {
        unsigned char seen[256] = {0};
        int distinct = 0;

        for (i = 0; i < WINDOW; i++)
            if (!seen[priv[off + i]]++)
                distinct++;
        if (distinct < WINDOW / 2)
            continue;
        memcpy(window, priv + off, WINDOW);
        found = !contains_window(pub, publen);
    }

end:
    OPENSSL_clear_free(priv, privlen);
    OPENSSL_free(pub);
    return found;
}

// The decoder frees the key it made once this returns
static int note_key(OSSL_DECODER_INSTANCE *inst, const OSSL_PARAM *params,
                    void *arg) {
    *(int *)arg =
        OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE) != NULL;
    return 1;
}

// Encodes the private key to PEM PrivateKeyInfo and decodes it from DER, and
// checks that no block freed meanwhile still holds key bytes.  Only the
// oqsprovider decoder is used: OpenSSL adds its own DER decoders in front when
// asked for an EVP_PKEY, and those read the same input.
static int test_privkey_cleanse(const char *algname) {
    EVP_PKEY *key = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    OSSL_DECODER *decoder = NULL;
    BIO *pem = NULL;
    unsigned char *der = NULL;
    const unsigned char *derp;
    size_t derlen = 0, len;
    int decoded = 0, testresult = 0;

    if (!alg_is_enabled(algname)) {
        fprintf(stderr, "Not testing disabled algorithm %s.\n", algname);
        return 1;
    }

    if ((key = EVP_PKEY_Q_keygen(libctx, OQSPROV_PROPQ, algname)) == NULL ||
        (pem = BIO_new(BIO_s_mem())) == NULL)
        goto end;
    if (!pick_window(key)) {
        fprintf(stderr,
                cYELLOW "  No usable private key bytes, skipping\n" cNORM);
        testresult = 1;
        goto end;
    }

    // DER input for the decoder, made before scanning starts
    ectx = OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_KEYPAIR, "DER",
                                         "PrivateKeyInfo", OQSPROV_PROPQ);
    if (ectx == NULL || !OSSL_ENCODER_to_data(ectx, &der, &derlen))
        goto end;
    OSSL_ENCODER_CTX_free(ectx);

    leaks = 0;
    armed = 1;
    ectx = OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_KEYPAIR, "PEM",
                                         "PrivateKeyInfo", OQSPROV_PROPQ);
    if (ectx == NULL || !OSSL_ENCODER_to_bio(ectx, pem)) {
        armed = 0;
        goto end;
    }

    derp = der;
    len = derlen;
    if ((decoder = OSSL_DECODER_fetch(
             libctx, algname,
             OQSPROV_PROPQ ",input=der,structure=PrivateKeyInfo")) == NULL ||
        (dctx = OSSL_DECODER_CTX_new()) == NULL ||
        !OSSL_DECODER_CTX_add_decoder(dctx, decoder) ||
        !OSSL_DECODER_CTX_set_input_type(dctx, "DER") ||
        !OSSL_DECODER_CTX_set_selection(dctx, EVP_PKEY_KEYPAIR) ||
        !OSSL_DECODER_CTX_set_construct(dctx, note_key) ||
        !OSSL_DECODER_CTX_set_construct_data(dctx, &decoded) ||
        !OSSL_DECODER_from_data(dctx, &derp, &len) || !decoded) {
        armed = 0;
        goto end;
    }
    armed = 0;

    testresult = leaks == 0;

end:
    OSSL_DECODER_CTX_free(dctx);
    OSSL_DECODER_free(decoder);
    OSSL_ENCODER_CTX_free(ectx);
    OPENSSL_clear_free(der, derlen);
    BIO_free(pem);
    EVP_PKEY_free(key);
    return testresult;
}

int main(int argc, char *argv[]) {
    int query_nocache;
    OSSL_PROVIDER *oqsprov = NULL;
    const OSSL_ALGORITHM *algs;
    int errcnt = 0, test = 0;

    T(CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free) == 1);

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    load_oqs_provider(libctx, modulename, configfile);

    oqsprov = OSSL_PROVIDER_load(libctx, modulename);
    algs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE,
                                         &query_nocache);
    T(algs != NULL);

    // Hybrid keys also hold a classical key, whose handling is OpenSSL's
    for (; algs->algorithm_names != NULL; ++algs) {
        const char *name = algs->algorithm_names;

        if (is_signature_algorithm_hybrid(name))
            continue;
        fprintf(stderr, cGREEN "  Testing private key cleanse for %s\n" cNORM,
                name);
        TEST_ASSERT(test_privkey_cleanse(name))
        if (!test)
            errcnt++;
    }

    OSSL_PROVIDER_unload(oqsprov);
    OSSL_LIB_CTX_free(libctx);

    TEST_ASSERT(errcnt == 0)
    return !test;
}
