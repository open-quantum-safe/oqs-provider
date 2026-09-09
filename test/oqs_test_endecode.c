// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <limits.h>
#include <openssl/asn1.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/trace.h>
#include <stdint.h>
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

#ifdef OQS_KEM_ENCODERS
static char *format_component(const char *label, const unsigned char *buf,
                              size_t buflen) {
    BIO *out = NULL;
    BUF_MEM *mem = NULL;
    char *formatted = NULL;
    size_t i;

    out = BIO_new(BIO_s_mem());
    if (out == NULL || (label != NULL && BIO_printf(out, "%s\n", label) <= 0))
        goto end;

    for (i = 0; i < buflen; i++) {
        if ((i % 15) == 0) {
            if (i > 0 && BIO_printf(out, "\n") <= 0)
                goto end;
            if (BIO_printf(out, "    ") <= 0)
                goto end;
        }
        if (BIO_printf(out, "%02x%s", buf[i], (i == buflen - 1) ? "" : ":") <=
            0)
            goto end;
    }
    if (BIO_printf(out, "\n") <= 0)
        goto end;

    BIO_get_mem_ptr(out, &mem);
    if (mem == NULL)
        goto end;
    formatted = OPENSSL_malloc(mem->length + 1);
    if (formatted == NULL)
        goto end;
    memcpy(formatted, mem->data, mem->length);
    formatted[mem->length] = '\0';

end:
    BIO_free(out);
    return formatted;
}

static int text_contains_component(const BUF_MEM *encoded, const char *label,
                                   const unsigned char *component,
                                   size_t component_len) {
    char *formatted = NULL;
    char *text = NULL;
    int ok = 0;

    formatted = format_component(label, component, component_len);
    text = OPENSSL_malloc(encoded->length + 1);
    if (formatted == NULL || text == NULL)
        goto end;
    memcpy(text, encoded->data, encoded->length);
    text[encoded->length] = '\0';
    ok = strstr(text, formatted) != NULL;

end:
    OPENSSL_free(formatted);
    OPENSSL_free(text);
    return ok;
}

static int test_hybrid_kem_text_components(const char *alg_name) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL, *pubonly = NULL;
    OSSL_PARAM *public_params = NULL;
    BUF_MEM *keypair_text = NULL, *public_text = NULL;
    unsigned char *classic_pub = NULL, *classic_priv = NULL;
    unsigned char *pq_pub = NULL, *pq_priv = NULL;
    size_t classic_pub_len = 0, classic_priv_len = 0;
    size_t pq_pub_len = 0, pq_priv_len = 0;
    int ok = 0;

    if (!alg_is_enabled(alg_name))
        return 1;

    key = oqstest_make_key(alg_name, NULL, NULL);
    if (key == NULL ||
        get_param_octet_string(key, OQS_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY,
                               &classic_pub, &classic_pub_len) != 0 ||
        get_param_octet_string(key, OQS_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY,
                               &classic_priv, &classic_priv_len) != 0 ||
        get_param_octet_string(key, OQS_HYBRID_PKEY_PARAM_PQ_PUB_KEY, &pq_pub,
                               &pq_pub_len) != 0 ||
        get_param_octet_string(key, OQS_HYBRID_PKEY_PARAM_PQ_PRIV_KEY, &pq_priv,
                               &pq_priv_len) != 0)
        goto end;

    if (!encode_EVP_PKEY_prov(key, "TEXT", NULL, NULL,
                              OSSL_KEYMGMT_SELECT_KEYPAIR, &keypair_text) ||
        !text_contains_component(keypair_text, NULL, classic_priv,
                                 classic_priv_len) ||
        !text_contains_component(keypair_text, "PQ key material:", pq_priv,
                                 pq_priv_len) ||
        !text_contains_component(keypair_text, NULL, classic_pub,
                                 classic_pub_len) ||
        !text_contains_component(keypair_text, "PQ key material:", pq_pub,
                                 pq_pub_len))
        goto end;

    if (EVP_PKEY_todata(key, EVP_PKEY_PUBLIC_KEY, &public_params) != 1)
        goto end;
    ctx = EVP_PKEY_CTX_new_from_name(keyctx, alg_name, OQSPROV_PROPQ);
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, &pubonly, EVP_PKEY_PUBLIC_KEY, public_params) !=
            1)
        goto end;
    if (!encode_EVP_PKEY_prov(pubonly, "TEXT", NULL, NULL,
                              OSSL_KEYMGMT_SELECT_PUBLIC_KEY, &public_text) ||
        !text_contains_component(public_text, NULL, classic_pub,
                                 classic_pub_len) ||
        !text_contains_component(public_text, "PQ key material:", pq_pub,
                                 pq_pub_len))
        goto end;

    ok = 1;

end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    EVP_PKEY_free(pubonly);
    OSSL_PARAM_free(public_params);
    BUF_MEM_free(keypair_text);
    BUF_MEM_free(public_text);
    free(classic_pub);
    free(classic_priv);
    free(pq_pub);
    free(pq_priv);
    return ok;
}
#endif

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

enum hybrid_length_test_result {
    HYBRID_LENGTH_TEST_FAILED = 0,
    HYBRID_LENGTH_TEST_PASSED = 1,
    HYBRID_LENGTH_TEST_SKIP_DISABLED = -1,
    HYBRID_LENGTH_TEST_SKIP_NO_CLASSICAL = -2,
};

static int get_optional_octet_string_param(const EVP_PKEY *key,
                                           const char *param_name,
                                           unsigned char **value,
                                           size_t *value_len) {
    *value = NULL;
    *value_len = 0;

    if (EVP_PKEY_get_octet_string_param(key, param_name, NULL, 0, value_len) !=
            1 ||
        *value_len == 0) {
        ERR_clear_error();
        return 0;
    }
    *value = malloc(*value_len);
    if (*value == NULL)
        return -1;
    if (EVP_PKEY_get_octet_string_param(key, param_name, *value, *value_len,
                                        value_len) != 1) {
        free(*value);
        *value = NULL;
        return -1;
    }
    return 1;
}

static unsigned char *locate_classical_public_key(
    unsigned char *public_key, size_t public_key_len,
    const unsigned char *classical_public_key, size_t classical_public_key_len,
    const unsigned char *pq_public_key, size_t pq_public_key_len) {
    unsigned char *components;
    uint32_t encoded_classical_len;

    if (classical_public_key_len > SIZE_MAX - SIZE_OF_UINT32 ||
        pq_public_key_len >
            SIZE_MAX - SIZE_OF_UINT32 - classical_public_key_len ||
        public_key_len !=
            SIZE_OF_UINT32 + classical_public_key_len + pq_public_key_len ||
        classical_public_key_len > UINT32_MAX)
        return NULL;

    DECODE_UINT32(encoded_classical_len, public_key);
    if (encoded_classical_len != classical_public_key_len)
        return NULL;

    /* Hybrid public keys contain either CLASSICAL || PQ or PQ || CLASSICAL. */
    components = public_key + SIZE_OF_UINT32;
    if (memcmp(components, classical_public_key, classical_public_key_len) ==
            0 &&
        memcmp(components + classical_public_key_len, pq_public_key,
               pq_public_key_len) == 0)
        return components;

    if (memcmp(components, pq_public_key, pq_public_key_len) == 0 &&
        memcmp(components + pq_public_key_len, classical_public_key,
               classical_public_key_len) == 0)
        return components + pq_public_key_len;

    return NULL;
}

static unsigned char *get_spki_public_key(BUF_MEM *spki,
                                          const unsigned char *expected,
                                          size_t expected_len) {
    const unsigned char *cursor, *outer_end;
    long object_len;
    int object_class, object_tag, ret;

    if (spki == NULL || spki->data == NULL || spki->length > LONG_MAX)
        return NULL;

    cursor = (const unsigned char *)spki->data;
    /* Walk SubjectPublicKeyInfo structurally to its subjectPublicKey BIT
     * STRING. */
    ret = ASN1_get_object(&cursor, &object_len, &object_tag, &object_class,
                          (long)spki->length);
    if ((ret & 0x80) != 0 || (ret & V_ASN1_CONSTRUCTED) == 0 ||
        object_class != V_ASN1_UNIVERSAL || object_tag != V_ASN1_SEQUENCE ||
        object_len < 0 ||
        (size_t)object_len >
            spki->length -
                (size_t)(cursor - (const unsigned char *)spki->data) ||
        cursor + object_len != (const unsigned char *)spki->data + spki->length)
        return NULL;
    outer_end = cursor + object_len;

    ret = ASN1_get_object(&cursor, &object_len, &object_tag, &object_class,
                          (long)(outer_end - cursor));
    if ((ret & 0x80) != 0 || (ret & V_ASN1_CONSTRUCTED) == 0 ||
        object_class != V_ASN1_UNIVERSAL || object_tag != V_ASN1_SEQUENCE ||
        object_len < 0 || object_len > outer_end - cursor)
        return NULL;
    cursor += object_len;

    ret = ASN1_get_object(&cursor, &object_len, &object_tag, &object_class,
                          (long)(outer_end - cursor));
    if ((ret & 0x80) != 0 || (ret & V_ASN1_CONSTRUCTED) != 0 ||
        object_class != V_ASN1_UNIVERSAL || object_tag != V_ASN1_BIT_STRING ||
        object_len < 1 || object_len - 1 != expected_len ||
        object_len > outer_end - cursor || cursor[0] != 0 ||
        cursor + object_len != outer_end ||
        memcmp(cursor + 1, expected, expected_len) != 0)
        return NULL;

    return (unsigned char *)cursor + 1;
}

static enum hybrid_length_test_result
test_hybrid_kem_rejects_invalid_classical_length(const char *alg_name) {
    EVP_PKEY *key = NULL, *decoded = NULL;
    BUF_MEM *spki = NULL;
    unsigned char *public_key = NULL, *private_key = NULL;
    unsigned char *classical_public_key = NULL, *classical_in_public = NULL;
    unsigned char *pq_public_key = NULL, *spki_public_key = NULL;
    unsigned char *classical_in_spki = NULL;
    size_t public_key_len = 0, private_key_len = 0;
    size_t classical_public_key_len = 0, pq_public_key_len = 0;
    int param_status;
    enum hybrid_length_test_result result = HYBRID_LENGTH_TEST_FAILED;

    if (!alg_is_enabled(alg_name))
        return HYBRID_LENGTH_TEST_SKIP_DISABLED;
    key = oqstest_make_key(alg_name, NULL, NULL);
    if (key == NULL)
        goto end;

    param_status = get_optional_octet_string_param(
        key, OQS_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY, &classical_public_key,
        &classical_public_key_len);
    if (param_status == 0) {
        result = HYBRID_LENGTH_TEST_SKIP_NO_CLASSICAL;
        goto end;
    }
    if (param_status < 0)
        goto end;
    if (get_optional_octet_string_param(key, OQS_HYBRID_PKEY_PARAM_PQ_PUB_KEY,
                                        &pq_public_key,
                                        &pq_public_key_len) != 1)
        goto end;
    if (get_param_octet_string(key, OSSL_PKEY_PARAM_PUB_KEY, &public_key,
                               &public_key_len) != 0 ||
        get_param_octet_string(key, OSSL_PKEY_PARAM_PRIV_KEY, &private_key,
                               &private_key_len) != 0)
        goto end;

    classical_in_public = locate_classical_public_key(
        public_key, public_key_len, classical_public_key,
        classical_public_key_len, pq_public_key, pq_public_key_len);
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

        spki_public_key = get_spki_public_key(spki, public_key, public_key_len);
        if (spki_public_key == NULL)
            goto end;
        classical_in_spki =
            spki_public_key + (classical_in_public - public_key);
    }

    public_key[0] = public_key[1] = public_key[2] = 0;
    public_key[3] = 1;
    classical_in_public[0] = 0;
    if (spki_public_key != NULL) {
        spki_public_key[0] = spki_public_key[1] = spki_public_key[2] = 0;
        spki_public_key[3] = 1;
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
    result = HYBRID_LENGTH_TEST_PASSED;

end:
    EVP_PKEY_free(key);
    EVP_PKEY_free(decoded);
    BUF_MEM_free(spki);
    free(public_key);
    free(private_key);
    free(classical_public_key);
    free(pq_public_key);
    return result;
}

static int
test_hybrid_kems_reject_invalid_classical_lengths(const OSSL_ALGORITHM *algs) {
    int discovered = 0, disabled = 0, no_classical = 0;
    int errcnt = 0, tested = 0, spki_tested = 0;

    for (; algs->algorithm_names != NULL; algs++) {
        int has_spki = OBJ_sn2nid(algs->algorithm_names) != NID_undef;

        discovered++;
        switch (test_hybrid_kem_rejects_invalid_classical_length(
            algs->algorithm_names)) {
        case HYBRID_LENGTH_TEST_PASSED:
            fprintf(stderr,
                    cGREEN "  Invalid classical length rejected: %s" cNORM "\n",
                    algs->algorithm_names);
            tested++;
            spki_tested += has_spki;
            break;
        case HYBRID_LENGTH_TEST_SKIP_DISABLED:
            disabled++;
            break;
        case HYBRID_LENGTH_TEST_SKIP_NO_CLASSICAL:
            no_classical++;
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
    fprintf(stderr,
            cBLUE "  Invalid classical length coverage: discovered=%d, "
                  "tested=%d, spki=%d, skipped_disabled=%d, "
                  "skipped_no_classical=%d, failed=%d" cNORM "\n",
            discovered, tested, spki_tested, disabled, no_classical, errcnt);
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
        const OSSL_ALGORITHM *kemalgs;

        errcnt += test_algs(algs);
        for (kemalgs = algs; kemalgs->algorithm_names != NULL; kemalgs++) {
            if (!is_kem_algorithm_hybrid(kemalgs->algorithm_names))
                continue;
            if (!test_hybrid_kem_text_components(kemalgs->algorithm_names)) {
                fprintf(stderr,
                        cRED "  Hybrid KEM TEXT encoding test failed: %s" cNORM
                             "\n",
                        kemalgs->algorithm_names);
                ERR_print_errors_fp(stderr);
                errcnt++;
            }
        }
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
