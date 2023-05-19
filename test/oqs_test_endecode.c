// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <string.h>
#include "test_common.h"
#include <openssl/core_names.h>
#include <openssl/trace.h>
#include "oqs/oqs.h"

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;
static char *testpropq = NULL;
static OSSL_LIB_CTX *keyctx = NULL;
static OSSL_LIB_CTX *testctx = NULL;

static OSSL_PROVIDER *dfltprov = NULL;
static OSSL_PROVIDER *keyprov = NULL;

#define nelem(a) (sizeof(a)/sizeof((a)[0]))

typedef struct endecode_params_st {
    char *format;
    char *structure;
    char *keytype;
    char *pass;
    int selection;

} ENDECODE_PARAMS;

static ENDECODE_PARAMS test_params_list[] = {
        {"PEM", "PrivateKeyInfo",          NULL, NULL,
                                                                                         OSSL_KEYMGMT_SELECT_KEYPAIR |
                                                                                         OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
        {"PEM", "EncryptedPrivateKeyInfo", NULL, "Pass the holy handgrenade of antioch", OSSL_KEYMGMT_SELECT_KEYPAIR |
                                                                                         OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS},
        {"PEM", "SubjectPublicKeyInfo",    NULL, NULL,                                   OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                                                                                         OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
        {"DER", "PrivateKeyInfo",          NULL, NULL,                                   OSSL_KEYMGMT_SELECT_KEYPAIR |
                                                                                         OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
        {"DER", "EncryptedPrivateKeyInfo", NULL, "Pass the holy handgrenade of antioch", OSSL_KEYMGMT_SELECT_KEYPAIR |
                                                                                         OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS},
        {"DER", "SubjectPublicKeyInfo",    NULL, NULL,                                   OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                                                                                         OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
};

static const char *sigalg_names[] = {
///// OQS_TEMPLATE_FRAGMENT_SIGNATURE_CASES_START
#ifdef OQS_ENABLE_SIG_dilithium_2
        "dilithium2","p256_dilithium2","rsa3072_dilithium2",
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3
        "dilithium3","p384_dilithium3",
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5
        "dilithium5","p521_dilithium5",
#endif
#ifdef OQS_ENABLE_SIG_falcon_512
        "falcon512","p256_falcon512","rsa3072_falcon512",
#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
        "falcon1024","p521_falcon1024",
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128f_simple
        "sphincssha2128fsimple","p256_sphincssha2128fsimple","rsa3072_sphincssha2128fsimple",
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128s_simple
        "sphincssha2128ssimple","p256_sphincssha2128ssimple","rsa3072_sphincssha2128ssimple",
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_192f_simple
        "sphincssha2192fsimple","p384_sphincssha2192fsimple",
#endif
#ifdef OQS_ENABLE_SIG_sphincs_shake_128f_simple
        "sphincsshake128fsimple","p256_sphincsshake128fsimple","rsa3072_sphincsshake128fsimple",
#endif

///// OQS_TEMPLATE_FRAGMENT_SIGNATURE_CASES_END
};

static EVP_PKEY *oqstest_make_key(const char *type, EVP_PKEY *template,
                                  OSSL_PARAM *genparams) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (!alg_is_enabled(type)) {
        printf("Not generating key for disabled algorithm %s.\n", type);
        return NULL;
    }

    ctx = (template != NULL)
          ? EVP_PKEY_CTX_new_from_pkey(keyctx, template, testpropq)
          : EVP_PKEY_CTX_new_from_name(keyctx, type, testpropq);

    /*
     * No real need to check the errors other than for the cascade
     * effect.  |pkey| will simply remain NULL if something goes wrong.
     */
    (void) (ctx != NULL
            && EVP_PKEY_keygen_init(ctx) > 0
            && (genparams == NULL
                || EVP_PKEY_CTX_set_params(ctx, genparams) > 0)
            && EVP_PKEY_keygen(ctx, &pkey) > 0);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int encode_EVP_PKEY_prov(const EVP_PKEY *pkey, const char *format, const char *structure, const char *pass,
                                const int selection, void **encoded, long *encoded_len) {
    OSSL_ENCODER_CTX *ectx;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    const char *cipher = "AES-256-CBC";
    int ok = 0;

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey,
                                         selection,
                                         format, structure,
                                         NULL);
    if (ectx == NULL) {
        printf("No suitable encoder found\n");
        goto end;
    }

    if (pass != NULL) {
        OSSL_ENCODER_CTX_set_passphrase(ectx, (const unsigned char *) pass, strlen(pass));
        OSSL_ENCODER_CTX_set_cipher(ectx, cipher, NULL);
    }
    mem_ser = BIO_new(BIO_s_mem());
    if (!OSSL_ENCODER_to_bio(ectx, mem_ser)) {
        /* encoding failure */
        goto end;
    }

    BIO_get_mem_ptr(mem_ser, &mem_buf);
    if (mem_buf == NULL || mem_buf->length == 0)
        goto end;

    /* pkey was successfully encoded into the bio */
    *encoded = mem_buf->data;
    *encoded_len = mem_buf->length;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;

    end:
    BIO_free(mem_ser);
    OSSL_ENCODER_CTX_free(ectx);
    return ok;
}

static int decode_EVP_PKEY_prov(const char *input_type, const char *structure, const char *pass,
                                const char *keytype, const int selection, EVP_PKEY **object,
                                const void *encoded, const long encoded_len) {
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    BIO *encoded_bio = NULL;

    int ok = 0;

    encoded_bio = BIO_new_mem_buf(encoded, encoded_len);
    if (encoded_bio == NULL)
        goto end;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey,
                                         input_type, structure,
                                         keytype, selection,
                                         keyctx, NULL);
    if (dctx == NULL)
        goto end;

    if (pass != NULL)
        OSSL_DECODER_CTX_set_passphrase(dctx, (const unsigned char *) pass, strlen(pass));

    if (!OSSL_DECODER_from_bio(dctx, encoded_bio))
        goto end;

    OSSL_DECODER_CTX_free(dctx);
    dctx = NULL;

    ok = 1;
    *object = pkey;
    pkey = NULL;

    end:
    EVP_PKEY_free(pkey);
    BIO_free(encoded_bio);
    OSSL_DECODER_CTX_free(dctx);
    return ok;
}

static int test_oqs_encdec(const char *sigalg_name) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *decoded_pkey = NULL;
    void *encoded = NULL;
    long encoded_len = 0;
    size_t i;
    int ok = 0;

    for (i = 0; i < nelem(test_params_list); i++) {

        pkey = oqstest_make_key(sigalg_name, NULL, NULL);
        if (pkey == NULL)
            goto end;


        if (!encode_EVP_PKEY_prov(pkey, test_params_list[i].format, test_params_list[i].structure,
                                  test_params_list[i].pass, test_params_list[i].selection,
                                  &encoded, &encoded_len)) {
            printf("Failed encoding %s", sigalg_name);
            goto end;
        }
        if (!decode_EVP_PKEY_prov(test_params_list[i].format, test_params_list[i].structure,
                                  test_params_list[i].pass, test_params_list[i].keytype,
                                  test_params_list[i].selection,
                                  &decoded_pkey, encoded, encoded_len)) {
            printf("Failed decoding %s", sigalg_name);
            goto end;
        }

        if (EVP_PKEY_eq(pkey, decoded_pkey) != 1)
            goto end;
    }
    ok = 1;
    end:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(decoded_pkey);
    return ok;
}

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0;

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    T(OSSL_LIB_CTX_load_config(libctx, configfile));

    T(OSSL_PROVIDER_available(libctx, modulename));
    keyctx = OSSL_LIB_CTX_new();
    dfltprov = OSSL_PROVIDER_load(NULL, "default");
    dfltprov = OSSL_PROVIDER_load(keyctx, "default");
    keyprov = OSSL_PROVIDER_load(keyctx, modulename);

    for (i = 0; i < nelem(sigalg_names); i++) {
        if (test_oqs_encdec(sigalg_names[i])) {
            fprintf(stderr,
                    cGREEN "  Encoding/Decoding test succeeded: %s" cNORM "\n",
                    sigalg_names[i]);
        } else {
            fprintf(stderr,
                    cRED "  Encoding/Decoding test failed: %s" cNORM "\n",
                    sigalg_names[i]);
            ERR_print_errors_fp(stderr);
            errcnt++;
        }
    }

    OSSL_LIB_CTX_free(libctx);
    OSSL_PROVIDER_unload(dfltprov);
    OSSL_PROVIDER_unload(keyprov);
    OSSL_LIB_CTX_free(keyctx);

    TEST_ASSERT(errcnt == 0)
    return !test;
}

