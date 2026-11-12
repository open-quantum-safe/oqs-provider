// SPDX-License-Identifier: Apache-2.0 AND MIT
//
// With "keep_standardized_algs = 1" in its config section, oqsprovider keeps
// offering ML-DSA and ML-KEM on OpenSSL >= 3.5, next to the default
// provider's. Checks that such a key uses the standard OIDs and interoperates
// with the default provider, and that hybrids stay disabled.
//
// Usage: oqs_test_keep_std <modulename> <config_file>
// Exits with 77 (skipped) on OpenSSL < 3.5.

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <string.h>

#include "test_common.h"

#ifdef OQS_PROVIDER_STATIC
extern OSSL_provider_init_fn oqs_provider_init;
#endif

#define MLDSA65_OID "2.16.840.1.101.3.4.3.18"

static int is_mldsa65_oid(const ASN1_OBJECT *obj) {
    char buf[64];

    return OBJ_obj2txt(buf, sizeof(buf), obj, 1) > 0 &&
           strcmp(buf, MLDSA65_OID) == 0;
}

int main(int argc, char *argv[]) {
    static const unsigned char msg[] = "keep standardized algorithms";
    /* DER AlgorithmIdentifier of id-ml-dsa-65, no parameters */
    static const unsigned char mldsa65_aid[] = {0x30, 0x0b, 0x06, 0x09, 0x60,
                                                0x86, 0x48, 0x01, 0x65, 0x03,
                                                0x04, 0x03, 0x12};
    OSSL_LIB_CTX *libctx;
    EVP_PKEY *key = NULL, *pub = NULL;
    EVP_PKEY_CTX *ctx;
    EVP_MD_CTX *mdctx;
    EVP_KEM *kem;
    PKCS8_PRIV_KEY_INFO *p8;
    X509_PUBKEY *xpk;
    const ASN1_OBJECT *obj;
    unsigned char *der = NULL, aid[64], sig[8192];
    const unsigned char *p;
    size_t siglen = sizeof(sig), aidlen;
    int derlen;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid,
                                sizeof(aid)),
        OSSL_PARAM_END};

    if (argc != 3) {
        fprintf(stderr, "usage: %s <modulename> <config_file>\n", argv[0]);
        return 1;
    }
    if (OpenSSL_version_num() < 0x30500000L) {
        fprintf(stderr, cYELLOW "OpenSSL < 3.5: nothing to keep, skipping "
                                "test" cNORM "\n");
        return 77;
    }

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
#ifdef OQS_PROVIDER_STATIC
    T(OSSL_PROVIDER_add_builtin(libctx, argv[1], oqs_provider_init));
#endif
    T(OSSL_LIB_CTX_load_config(libctx, argv[2]));
    T(OSSL_PROVIDER_available(libctx, argv[1]));

    /* ML-DSA-65 key from oqsprovider */
    T((ctx = EVP_PKEY_CTX_new_from_name(libctx, "mldsa65",
                                        "provider=oqsprovider")) != NULL);
    T(EVP_PKEY_keygen_init(ctx) > 0);
    T(EVP_PKEY_generate(ctx, &key) > 0);
    EVP_PKEY_CTX_free(ctx);
    T(strcmp(OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(key)),
             "oqsprovider") == 0);

    /* PKCS#8 and SPKI carry the standard OID */
    T((p8 = EVP_PKEY2PKCS8(key)) != NULL);
    T(PKCS8_pkey_get0(&obj, NULL, NULL, NULL, p8));
    T(is_mldsa65_oid(obj));
    PKCS8_PRIV_KEY_INFO_free(p8);
    T((derlen = i2d_PUBKEY(key, &der)) > 0);
    p = der;
    T((xpk = d2i_X509_PUBKEY(NULL, &p, derlen)) != NULL);
    T(X509_PUBKEY_get0_param((ASN1_OBJECT **)&obj, NULL, NULL, NULL, xpk));
    T(is_mldsa65_oid(obj));
    X509_PUBKEY_free(xpk);

    /* The default provider reads the public key */
    p = der;
    T((pub = d2i_PUBKEY_ex(NULL, &p, derlen, libctx, "provider=default")) !=
      NULL);
    T(strcmp(OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(pub)), "default") ==
      0);
    OPENSSL_free(der);

    /* oqsprovider signs, with the standard AlgorithmIdentifier ... */
    T((ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=oqsprovider")) !=
      NULL);
    T(EVP_PKEY_sign_init(ctx) > 0);
    T(strcmp(OSSL_PROVIDER_get0_name(EVP_PKEY_CTX_get0_provider(ctx)),
             "oqsprovider") == 0);
    T(EVP_PKEY_sign(ctx, sig, &siglen, msg, sizeof(msg)) > 0);
    T(EVP_PKEY_CTX_get_params(ctx, params));
    aidlen = params[0].return_size;
    T(aidlen == sizeof(mldsa65_aid) && memcmp(aid, mldsa65_aid, aidlen) == 0);
    EVP_PKEY_CTX_free(ctx);

    /* ... and the default provider verifies */
    T((mdctx = EVP_MD_CTX_new()) != NULL);
    T(EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, libctx, "provider=default",
                              pub, NULL) > 0);
    T(EVP_DigestVerify(mdctx, sig, siglen, msg, sizeof(msg)) == 1);
    EVP_MD_CTX_free(mdctx);

    /* ML-KEM is kept too, the hybrids are not */
    T((kem = EVP_KEM_fetch(libctx, "mlkem768", "provider=oqsprovider")) !=
      NULL);
    EVP_KEM_free(kem);
    T(EVP_KEM_fetch(libctx, "X25519MLKEM768", "provider=oqsprovider") == NULL);
    ERR_clear_error();

    EVP_PKEY_free(pub);
    EVP_PKEY_free(key);
    OSSL_LIB_CTX_free(libctx);
    fprintf(stderr, cGREEN "keep_standardized_algs test passed" cNORM "\n");
    return 0;
}
