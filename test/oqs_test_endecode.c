// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/trace.h>
#include <stdlib.h>
#include <string.h>

#include "oqs/oqs.h"
#include "oqs_prov.h"
#include "test_common.h"

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;
static OSSL_LIB_CTX *keyctx = NULL;
static OSSL_LIB_CTX *testctx = NULL;

static OSSL_PROVIDER *dfltprov = NULL;
static OSSL_PROVIDER *keyprov = NULL;

#define nelem(a) (sizeof(a) / sizeof((a)[0]))

typedef struct endecode_params_st {
    char *format;
    char *structure;
    char *keytype;
    char *pass;
    int selection;

} ENDECODE_PARAMS;

static ENDECODE_PARAMS test_params_list[] = {
    {"PEM", "PrivateKeyInfo", NULL, NULL,
     OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
    {"PEM", "EncryptedPrivateKeyInfo", NULL,
     "Pass the holy handgrenade of antioch",
     OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS},
    {"PEM", "SubjectPublicKeyInfo", NULL, NULL,
     OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
    {"DER", "PrivateKeyInfo", NULL, NULL,
     OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
    {"DER", "EncryptedPrivateKeyInfo", NULL,
     "Pass the holy handgrenade of antioch",
     OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS},
    {"DER", "SubjectPublicKeyInfo", NULL, NULL,
     OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS},
};

static EVP_PKEY *oqstest_make_key(const char *type, EVP_PKEY *template,
                                  OSSL_PARAM *genparams) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (!alg_is_enabled(type)) {
        fprintf(stderr, "Not generating key for disabled algorithm %s.\n",
                type);
        return NULL;
    }

    ctx = (template != NULL)
              ? EVP_PKEY_CTX_new_from_pkey(keyctx, template, OQSPROV_PROPQ)
              : EVP_PKEY_CTX_new_from_name(keyctx, type, OQSPROV_PROPQ);

    /*
     * No real need to check the errors other than for the cascade
     * effect.  |pkey| will simply remain NULL if something goes wrong.
     */
    (void)(ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0 &&
           (genparams == NULL || EVP_PKEY_CTX_set_params(ctx, genparams) > 0) &&
           EVP_PKEY_keygen(ctx, &pkey) > 0);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int encode_EVP_PKEY_prov(const EVP_PKEY *pkey, const char *format,
                                const char *structure, const char *pass,
                                const int selection, BUF_MEM **encoded) {
    OSSL_ENCODER_CTX *ectx;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    const char *cipher = "AES-256-CBC";
    int ok = 0;

    ectx =
        OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, format, structure, NULL);
    if (ectx == NULL) {
        fprintf(stderr, "No suitable encoder found\n");
        goto end;
    }

    if (pass != NULL) {
        OSSL_ENCODER_CTX_set_passphrase(ectx, (const unsigned char *)pass,
                                        strlen(pass));
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
    *encoded = BUF_MEM_new();
    (*encoded)->data = mem_buf->data;
    (*encoded)->length = mem_buf->length;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;

end:
    BIO_free(mem_ser);
    OSSL_ENCODER_CTX_free(ectx);
    return ok;
}

static int decode_EVP_PKEY_prov(const char *input_type, const char *structure,
                                const char *pass, const char *keytype,
                                const int selection, EVP_PKEY **object,
                                const void *encoded, const long encoded_len) {
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    BIO *encoded_bio = NULL;

    int ok = 0;

    encoded_bio = BIO_new_mem_buf(encoded, encoded_len);
    if (encoded_bio == NULL)
        goto end;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, input_type, structure, keytype,
                                         selection, keyctx, NULL);
    if (dctx == NULL)
        goto end;

    if (pass != NULL)
        OSSL_DECODER_CTX_set_passphrase(dctx, (const unsigned char *)pass,
                                        strlen(pass));

    if (!OSSL_DECODER_from_bio(dctx, encoded_bio))
        goto end;

    OSSL_DECODER_CTX_free(dctx);
    dctx = NULL;

    ok = 1;
    *object = pkey;
    pkey = NULL;

end:
    BIO_free(encoded_bio);
    OSSL_DECODER_CTX_free(dctx);
    EVP_PKEY_free(pkey);
    return ok;
}

#ifdef OQS_KEM_ENCODERS
static unsigned char *find_bytes(unsigned char *haystack, size_t haystack_len,
                                 const unsigned char *needle,
                                 size_t needle_len) {
    size_t i;

    if (needle_len == 0 || haystack_len < needle_len)
        return NULL;
    for (i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0)
            return haystack + i;
    }
    return NULL;
}

static int import_hybrid_key(const char *alg_name, int selection,
                             unsigned char *public_key, size_t public_key_len,
                             unsigned char *private_key,
                             size_t private_key_len) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[3];
    int ok = 0;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  public_key, public_key_len);
    if (selection == EVP_PKEY_KEYPAIR) {
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, private_key, private_key_len);
        params[2] = OSSL_PARAM_construct_end();
    } else {
        params[1] = OSSL_PARAM_construct_end();
    }

    ctx = EVP_PKEY_CTX_new_from_name(keyctx, alg_name, OQSPROV_PROPQ);
    ok = ctx != NULL && EVP_PKEY_fromdata_init(ctx) == 1 &&
         EVP_PKEY_fromdata(ctx, &key, selection, params) == 1;
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int get_classical_public_key(const EVP_PKEY *key,
                                    unsigned char **classical_public_key,
                                    size_t *classical_public_key_len) {
    *classical_public_key = NULL;
    *classical_public_key_len = 0;

    if (EVP_PKEY_get_octet_string_param(
            key, OQS_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY, NULL, 0,
            classical_public_key_len) != 1 ||
        *classical_public_key_len == 0) {
        ERR_clear_error();
        return 0;
    }
    *classical_public_key = malloc(*classical_public_key_len);
    if (*classical_public_key == NULL)
        return -1;
    if (EVP_PKEY_get_octet_string_param(
            key, OQS_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY, *classical_public_key,
            *classical_public_key_len, classical_public_key_len) != 1) {
        free(*classical_public_key);
        *classical_public_key = NULL;
        return -1;
    }
    return 1;
}

static int
test_hybrid_kem_rejects_invalid_classical_length(const char *alg_name) {
    EVP_PKEY *key = NULL, *decoded = NULL;
    BUF_MEM *spki = NULL;
    unsigned char *public_key = NULL, *private_key = NULL;
    unsigned char *classical_public_key = NULL, *classical_in_public = NULL;
    unsigned char *embedded = NULL, *classical_in_spki = NULL;
    size_t public_key_len = 0, private_key_len = 0;
    size_t classical_public_key_len = 0;
    int classical_key_status;
    int ok = 0;

    if (!alg_is_enabled(alg_name))
        return -1;
    key = oqstest_make_key(alg_name, NULL, NULL);
    if (key == NULL)
        goto end;

    classical_key_status = get_classical_public_key(key, &classical_public_key,
                                                    &classical_public_key_len);
    if (classical_key_status == 0) {
        ok = -1;
        goto end;
    }
    if (classical_key_status < 0)
        goto end;
    if (classical_public_key_len < 2 || classical_public_key[0] != 0x04) {
        ok = -1;
        goto end;
    }
    if (get_param_octet_string(key, OSSL_PKEY_PARAM_PUB_KEY, &public_key,
                               &public_key_len) != 0 ||
        get_param_octet_string(key, OSSL_PKEY_PARAM_PRIV_KEY, &private_key,
                               &private_key_len) != 0)
        goto end;

    classical_in_public =
        public_key_len > 4
            ? find_bytes(public_key + 4, public_key_len - 4,
                         classical_public_key, classical_public_key_len)
            : NULL;
    if (classical_in_public == NULL)
        goto end;

    if (!import_hybrid_key(alg_name, EVP_PKEY_PUBLIC_KEY, public_key,
                           public_key_len, NULL, 0) ||
        !import_hybrid_key(alg_name, EVP_PKEY_KEYPAIR, public_key,
                           public_key_len, private_key, private_key_len))
        goto end;

    if (OBJ_sn2nid(alg_name) != NID_undef) {
        if (!encode_EVP_PKEY_prov(key, "DER", "SubjectPublicKeyInfo", NULL,
                                  EVP_PKEY_PUBLIC_KEY, &spki) ||
            !decode_EVP_PKEY_prov("DER", "SubjectPublicKeyInfo", NULL, alg_name,
                                  EVP_PKEY_PUBLIC_KEY, &decoded, spki->data,
                                  spki->length))
            goto end;
        EVP_PKEY_free(decoded);
        decoded = NULL;

        embedded = find_bytes((unsigned char *)spki->data, spki->length,
                              public_key, public_key_len);
        if (embedded == NULL)
            goto end;
        classical_in_spki = embedded + (classical_in_public - public_key);
    }

    public_key[0] = public_key[1] = public_key[2] = 0;
    public_key[3] = 1;
    classical_in_public[0] = 0;
    if (embedded != NULL) {
        embedded[0] = embedded[1] = embedded[2] = 0;
        embedded[3] = 1;
        classical_in_spki[0] = 0;
    }

    if (import_hybrid_key(alg_name, EVP_PKEY_PUBLIC_KEY, public_key,
                          public_key_len, NULL, 0) ||
        import_hybrid_key(alg_name, EVP_PKEY_KEYPAIR, public_key,
                          public_key_len, private_key, private_key_len) ||
        (spki != NULL &&
         decode_EVP_PKEY_prov("DER", "SubjectPublicKeyInfo", NULL, alg_name,
                              EVP_PKEY_PUBLIC_KEY, &decoded, spki->data,
                              spki->length)))
        goto end;

    ERR_clear_error();
    ok = 1;

end:
    EVP_PKEY_free(key);
    EVP_PKEY_free(decoded);
    BUF_MEM_free(spki);
    free(public_key);
    free(private_key);
    free(classical_public_key);
    return ok;
}

static int
test_hybrid_kems_reject_invalid_classical_lengths(const OSSL_ALGORITHM *algs) {
    int errcnt = 0, tested = 0;

    for (; algs->algorithm_names != NULL; algs++) {
        switch (test_hybrid_kem_rejects_invalid_classical_length(
            algs->algorithm_names)) {
        case 1:
            fprintf(stderr,
                    cGREEN "  Invalid classical length rejected: %s" cNORM "\n",
                    algs->algorithm_names);
            tested++;
            break;
        case -1:
            break;
        default:
            fprintf(stderr,
                    cRED "  Invalid classical length test failed: %s" cNORM
                         "\n",
                    algs->algorithm_names);
            ERR_print_errors_fp(stderr);
            errcnt++;
            break;
        }
    }
    if (tested == 0) {
        fprintf(stderr, cRED
                "  No hybrid KEM with a supported EC key found" cNORM "\n");
        errcnt++;
    }
    return errcnt;
}
#endif

static int test_oqs_encdec(const char *alg_name) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *decoded_pkey = NULL;
    BUF_MEM *encoded = NULL;
    size_t i;
    int ok = 0;

    for (i = 0; i < nelem(test_params_list); i++) {
        pkey = oqstest_make_key(alg_name, NULL, NULL);
        if (pkey == NULL)
            goto end;

        if (!OBJ_sn2nid(alg_name)) {
            fprintf(stderr, "No OID registered for %s\n", alg_name);
            ok = -1;
            goto end;
        }
        if (!encode_EVP_PKEY_prov(pkey, test_params_list[i].format,
                                  test_params_list[i].structure,
                                  test_params_list[i].pass,
                                  test_params_list[i].selection, &encoded)) {
            fprintf(stderr, "Failed encoding %s", alg_name);
            goto end;
        }
        if (!decode_EVP_PKEY_prov(
                test_params_list[i].format, test_params_list[i].structure,
                test_params_list[i].pass, test_params_list[i].keytype,
                test_params_list[i].selection, &decoded_pkey, encoded->data,
                encoded->length)) {
            fprintf(stderr, "Failed decoding %s", alg_name);
            goto end;
        }

        if (EVP_PKEY_eq(pkey, decoded_pkey) != 1) {
            fprintf(stderr, "Key equality failed for %s", alg_name);
            goto end;
        }
        EVP_PKEY_free(pkey);
        pkey = NULL;
        EVP_PKEY_free(decoded_pkey);
        decoded_pkey = NULL;
        BUF_MEM_free(encoded);
        encoded = NULL;
    }
    ok = 1;
end:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(decoded_pkey);
    BUF_MEM_free(encoded);
    return ok;
}

static int test_algs(const OSSL_ALGORITHM *algs) {
    int errcnt = 0;
    for (; algs->algorithm_names != NULL; algs++) {
        switch (test_oqs_encdec(algs->algorithm_names)) {
        case 1:
            fprintf(stderr,
                    cGREEN "  Encoding/Decoding test succeeded: %s" cNORM "\n",
                    algs->algorithm_names);
            break;
        case -1:
            fprintf(stderr,
                    cBLUE "  Encoding/Decoding test skipped: %s" cNORM "\n",
                    algs->algorithm_names);
            break;
        default:
            fprintf(stderr,
                    cRED "  Encoding/Decoding test failed: %s" cNORM "\n",
                    algs->algorithm_names);
            ERR_print_errors_fp(stderr);
            errcnt++;
            break;
        }
    }
    return errcnt;
}

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0, query_nocache;
    OSSL_PROVIDER *oqsprov = NULL;
    const OSSL_ALGORITHM *algs;

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    load_oqs_provider(libctx, modulename, configfile);

    keyctx = OSSL_LIB_CTX_new();

    load_oqs_provider(keyctx, modulename, configfile);

    dfltprov = OSSL_PROVIDER_load(keyctx, "default");
    keyprov = OSSL_PROVIDER_load(keyctx, modulename);
    oqsprov = OSSL_PROVIDER_load(libctx, modulename);

    algs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE,
                                         &query_nocache);

    if (algs) {
        errcnt += test_algs(algs);
    } else {
        fprintf(stderr, cRED "  No signature algorithms found" cNORM "\n");
        ERR_print_errors_fp(stderr);
        errcnt++;
    }

#ifdef OQS_KEM_ENCODERS
    algs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);

    if (algs) {
        errcnt += test_algs(algs);
    } else {
        fprintf(stderr, cRED "  No KEM algorithms found" cNORM "\n");
        ERR_print_errors_fp(stderr);
        errcnt++;
    }

    errcnt += test_hybrid_kems_reject_invalid_classical_lengths(algs);
#endif /* OQS_KEM_ENCODERS */

    OSSL_PROVIDER_unload(dfltprov);
    OSSL_PROVIDER_unload(keyprov);
    if (OPENSSL_VERSION_PREREQ(3, 1))
        OSSL_PROVIDER_unload(oqsprov); // avoid crash in 3.0.x
    OSSL_LIB_CTX_free(libctx);
    OSSL_LIB_CTX_free(keyctx);

    TEST_ASSERT(errcnt == 0)
    return !test;
}
