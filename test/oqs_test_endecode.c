// SPDX-License-Identifier: Apache-2.0 AND MIT

// Code strongly inspired by test of the same name in OpenSSL

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>

#include "crypto/pem.h"          /* For PVK and "blob" PEM headers */
#include "crypto/evp.h"          /* For evp_pkey_is_provided() */

#include "testutil.h" // output functions
#include "test_common.h"

/* Extended test macros to allow passing file & line number */
#define TEST_FL_ptr(a)               test_ptr(file, line, #a, a)
#define TEST_FL_mem_eq(a, m, b, n)   test_mem_eq(file, line, #a, #b, a, m, b, n)
#define TEST_FL_strn_eq(a, b, n)     test_strn_eq(file, line, #a, #b, a, n, b, n)
#define TEST_FL_strn2_eq(a, m, b, n) test_strn_eq(file, line, #a, #b, a, m, b, n)
#define TEST_FL_int_eq(a, b)         test_int_eq(file, line, #a, #b, a, b)
#define TEST_FL_int_ge(a, b)         test_int_ge(file, line, #a, #b, a, b)
#define TEST_FL_int_gt(a, b)         test_int_gt(file, line, #a, #b, a, b)
#define TEST_FL_long_gt(a, b)        test_long_gt(file, line, #a, #b, a, b)
#define TEST_FL_true(a)              test_true(file, line, #a, (a) != 0)

static int default_libctx = 1;

static OSSL_LIB_CTX *testctx = NULL;
static OSSL_LIB_CTX *keyctx = NULL;
static char *testpropq = NULL;

static OSSL_PROVIDER *oqsprov = NULL;
static OSSL_PROVIDER *dfltprov = NULL;
static OSSL_PROVIDER *keyprov = NULL;

static EVP_PKEY *oqstest_make_template(const char *type, OSSL_PARAM *genparams)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /*
     * No real need to check the errors other than for the cascade
     * effect.  |pkey| will simply remain NULL if something goes wrong.
     */
    (void)((ctx = EVP_PKEY_CTX_new_from_name(keyctx, type, testpropq)) != NULL
           && EVP_PKEY_paramgen_init(ctx) > 0
           && (genparams == NULL
               || EVP_PKEY_CTX_set_params(ctx, genparams) > 0)
           && EVP_PKEY_generate(ctx, &pkey) > 0);
    EVP_PKEY_CTX_free(ctx);

    return pkey;
}

static EVP_PKEY *oqstest_make_key(const char *type, EVP_PKEY *template,
                          OSSL_PARAM *genparams)
{
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
    (void)(ctx != NULL
           && EVP_PKEY_keygen_init(ctx) > 0
           && (genparams == NULL
               || EVP_PKEY_CTX_set_params(ctx, genparams) > 0)
           && EVP_PKEY_keygen(ctx, &pkey) > 0);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Main test driver */

typedef int (encoder)(const char *file, const int line,
                      void **encoded, long *encoded_len,
                      void *object, int selection,
                      const char *output_type, const char *output_structure,
                      const char *pass, const char *pcipher);
typedef int (decoder)(const char *file, const int line,
                      void **object, void *encoded, long encoded_len,
                      const char *input_type, const char *structure_type,
                      const char *keytype, int selection, const char *pass);
typedef int (tester)(const char *file, const int line,
                     const void *data1, size_t data1_len,
                     const void *data2, size_t data2_len);
typedef int (checker)(const char *file, const int line,
                      const char *type, const void *data, size_t data_len);
typedef void (dumper)(const char *label, const void *data, size_t data_len);

#define FLAG_DECODE_WITH_TYPE   0x0001

static int test_encode_decode(const char *file, const int line,
                              const char *type, EVP_PKEY *pkey,
                              int selection, const char *output_type,
                              const char *output_structure,
                              const char *pass, const char *pcipher,
                              encoder *encode_cb, decoder *decode_cb,
                              tester *test_cb, checker *check_cb,
                              dumper *dump_cb, int flags)
{
    void *encoded = NULL;
    long encoded_len = 0;
    EVP_PKEY *pkey2 = NULL;
    void *encoded2 = NULL;
    long encoded2_len = 0;
    int ok = 0;

    if (!alg_is_enabled(type)) {
        printf("Not testing disabled algorithm %s.\n", type);
        return 1;
    }

    /*
     * Encode |pkey|, decode the result into |pkey2|, and finish off by
     * encoding |pkey2| as well.  That last encoding is for checking and
     * dumping purposes.
     */
    if (!TEST_true(encode_cb(file, line, &encoded, &encoded_len, pkey, selection,
                             output_type, output_structure, pass, pcipher))
        || !TEST_true(check_cb(file, line, type, encoded, encoded_len))
        || !TEST_true(decode_cb(file, line, (void **)&pkey2, encoded, encoded_len,
                                output_type, output_structure,
                                (flags & FLAG_DECODE_WITH_TYPE ? type : NULL),
                                selection, pass))
        || !TEST_true(encode_cb(file, line, &encoded2, &encoded2_len, pkey2, selection,
                                output_type, output_structure, pass, pcipher)))
        goto end;

    if (selection == OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
        if (!TEST_int_eq(EVP_PKEY_parameters_eq(pkey, pkey2), 1))
            goto end;
    } else {
        if (!TEST_int_eq(EVP_PKEY_eq(pkey, pkey2), 1))
            goto end;
    }

    /*
     * Double check the encoding, but only for unprotected keys,
     * as protected keys have a random component, which makes the output
     * differ.
     */
    if ((pass == NULL && pcipher == NULL)
        && !test_cb(file, line, encoded, encoded_len, encoded2, encoded2_len))
        goto end;

    ok = 1;
 end:
    if (!ok) {
        if (encoded != NULL && encoded_len != 0)
            dump_cb("|pkey| encoded", encoded, encoded_len);
        if (encoded2 != NULL && encoded2_len != 0)
            dump_cb("|pkey2| encoded", encoded2, encoded2_len);
    }

    OPENSSL_free(encoded);
    OPENSSL_free(encoded2);
    EVP_PKEY_free(pkey2);
    return ok;
}

/* Encoding and decoding methods */

static int encode_EVP_PKEY_prov(const char *file, const int line,
                                void **encoded, long *encoded_len,
                                void *object, int selection,
                                const char *output_type,
                                const char *output_structure,
                                const char *pass, const char *pcipher)
{
    EVP_PKEY *pkey = object;
    OSSL_ENCODER_CTX *ectx = NULL;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    const unsigned char *upass = (const unsigned char *)pass;
    int ok = 0;

    if (!TEST_FL_ptr(ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection,
                                                       output_type,
                                                       output_structure,
                                                       testpropq))
        || !TEST_FL_int_gt(OSSL_ENCODER_CTX_get_num_encoders(ectx), 0)
        || (pass != NULL
            && !TEST_FL_true(OSSL_ENCODER_CTX_set_passphrase(ectx, upass,
                                                          strlen(pass))))
        || (pcipher != NULL
            && !TEST_FL_true(OSSL_ENCODER_CTX_set_cipher(ectx, pcipher, NULL)))
        || !TEST_FL_ptr(mem_ser = BIO_new(BIO_s_mem()))
        || !TEST_FL_true(OSSL_ENCODER_to_bio(ectx, mem_ser))
        || !TEST_FL_true(BIO_get_mem_ptr(mem_ser, &mem_buf) > 0)
        || !TEST_FL_ptr(*encoded = mem_buf->data)
        || !TEST_FL_long_gt(*encoded_len = mem_buf->length, 0))
        goto end;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    OSSL_ENCODER_CTX_free(ectx);
    return ok;
}

static int decode_EVP_PKEY_prov(const char *file, const int line,
                                void **object, void *encoded, long encoded_len,
                                const char *input_type,
                                const char *structure_type,
                                const char *keytype, int selection,
                                const char *pass)
{
    EVP_PKEY *pkey = NULL, *testpkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    BIO *encoded_bio = NULL;
    const unsigned char *upass = (const unsigned char *)pass;
    int ok = 0;
    int i;
    const char *badtype;

    if (strcmp(input_type, "DER") == 0)
        badtype = "PEM";
    else
        badtype = "DER";

    if (!TEST_FL_ptr(encoded_bio = BIO_new_mem_buf(encoded, encoded_len)))
        goto end;

    /*
     * We attempt the decode 3 times. The first time we provide the expected
     * starting input type. The second time we provide NULL for the starting
     * type. The third time we provide a bad starting input type.
     * The bad starting input type should fail. The other two should succeed
     * and produce the same result.
     */
    for (i = 0; i < 3; i++) {
        const char *testtype = (i == 0) ? input_type
                                        : ((i == 1) ? NULL : badtype);

        if (!TEST_FL_ptr(dctx = OSSL_DECODER_CTX_new_for_pkey(&testpkey,
                                                           testtype,
                                                           structure_type,
                                                           keytype,
                                                           selection,
                                                           testctx, testpropq))
            || (pass != NULL
                && !OSSL_DECODER_CTX_set_passphrase(dctx, upass, strlen(pass)))
            || !TEST_FL_int_gt(BIO_reset(encoded_bio), 0)
               /* We expect to fail when using a bad input type */
            || !TEST_FL_int_eq(OSSL_DECODER_from_bio(dctx, encoded_bio),
                            (i == 2) ? 0 : 1))
            goto end;
        OSSL_DECODER_CTX_free(dctx);
        dctx = NULL;

        if (i == 0) {
            pkey = testpkey;
            testpkey = NULL;
        } else if (i == 1) {
            if (selection == OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
                if (!TEST_FL_int_eq(EVP_PKEY_parameters_eq(pkey, testpkey), 1))
                    goto end;
            } else {
                if (!TEST_FL_int_eq(EVP_PKEY_eq(pkey, testpkey), 1))
                    goto end;
            }
        }
    }
    ok = 1;
    *object = pkey;
    pkey = NULL;

 end:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(testpkey);
    BIO_free(encoded_bio);
    OSSL_DECODER_CTX_free(dctx);
    return ok;
}

static int encode_EVP_PKEY_legacy_PEM(const char *file, const int line,
                                      void **encoded, long *encoded_len,
                                      void *object, ossl_unused int selection,
                                      ossl_unused const char *output_type,
                                      ossl_unused const char *output_structure,
                                      const char *pass, const char *pcipher)
{
    EVP_PKEY *pkey = object;
    EVP_CIPHER *cipher = NULL;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    const unsigned char *upass = (const unsigned char *)pass;
    size_t passlen = 0;
    int ok = 0;

    if (pcipher != NULL && pass != NULL) {
        passlen = strlen(pass);
        if (!TEST_FL_ptr(cipher = EVP_CIPHER_fetch(testctx, pcipher, testpropq)))
            goto end;
    }
    if (!TEST_FL_ptr(mem_ser = BIO_new(BIO_s_mem()))
        || !TEST_FL_true(PEM_write_bio_PrivateKey_traditional(mem_ser, pkey,
                                                           cipher,
                                                           upass, passlen,
                                                           NULL, NULL))
        || !TEST_FL_true(BIO_get_mem_ptr(mem_ser, &mem_buf) > 0)
        || !TEST_FL_ptr(*encoded = mem_buf->data)
        || !TEST_FL_long_gt(*encoded_len = mem_buf->length, 0))
        goto end;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    EVP_CIPHER_free(cipher);
    return ok;
}

static int encode_EVP_PKEY_MSBLOB(const char *file, const int line,
                                  void **encoded, long *encoded_len,
                                  void *object, int selection,
                                  ossl_unused const char *output_type,
                                  ossl_unused const char *output_structure,
                                  ossl_unused const char *pass,
                                  ossl_unused const char *pcipher)
{
    EVP_PKEY *pkey = object;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    int ok = 0;

    if (!TEST_FL_ptr(mem_ser = BIO_new(BIO_s_mem())))
        goto end;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!TEST_FL_int_ge(i2b_PrivateKey_bio(mem_ser, pkey), 0))
            goto end;
    } else {
        if (!TEST_FL_int_ge(i2b_PublicKey_bio(mem_ser, pkey), 0))
            goto end;
    }

    if (!TEST_FL_true(BIO_get_mem_ptr(mem_ser, &mem_buf) > 0)
        || !TEST_FL_ptr(*encoded = mem_buf->data)
        || !TEST_FL_long_gt(*encoded_len = mem_buf->length, 0))
        goto end;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    return ok;
}

static pem_password_cb pass_pw;
static int pass_pw(char *buf, int size, int rwflag, void *userdata)
{
    OPENSSL_strlcpy(buf, userdata, size);
    return strlen(userdata);
}

static int encode_EVP_PKEY_PVK(const char *file, const int line,
                               void **encoded, long *encoded_len,
                               void *object, int selection,
                               ossl_unused const char *output_type,
                               ossl_unused const char *output_structure,
                               const char *pass,
                               ossl_unused const char *pcipher)
{
    EVP_PKEY *pkey = object;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    int enc = (pass != NULL);
    int ok = 0;

    if (!TEST_FL_true(((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0))
        || !TEST_FL_ptr(mem_ser = BIO_new(BIO_s_mem()))
        || !TEST_FL_int_ge(i2b_PVK_bio_ex(mem_ser, pkey, enc,
                                          pass_pw, (void *)pass, testctx, testpropq), 0)
        || !TEST_FL_true(BIO_get_mem_ptr(mem_ser, &mem_buf) > 0)
        || !TEST_FL_ptr(*encoded = mem_buf->data)
        || !TEST_FL_long_gt(*encoded_len = mem_buf->length, 0))
        goto end;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    return ok;
}

static int test_text(const char *file, const int line,
                     const void *data1, size_t data1_len,
                     const void *data2, size_t data2_len)
{
    return TEST_FL_strn2_eq(data1, data1_len, data2, data2_len);
}

static int test_mem(const char *file, const int line,
                    const void *data1, size_t data1_len,
                    const void *data2, size_t data2_len)
{
    return TEST_FL_mem_eq(data1, data1_len, data2, data2_len);
}

/* Test cases and their dumpers / checkers */

static void collect_name(const char *name, void *arg)
{
    char **namelist = arg;
    char *new_namelist;
    size_t space;

    space = strlen(name);
    if (*namelist != NULL)
        space += strlen(*namelist) + 2 /* for comma and space */;
    space++; /* for terminating null byte */

    new_namelist = OPENSSL_realloc(*namelist, space);
    if (new_namelist == NULL)
        return;
    if (*namelist != NULL) {
        strcat(new_namelist, ", ");
        strcat(new_namelist, name);
    } else {
        strcpy(new_namelist, name);
    }
    *namelist = new_namelist;
}

static void dump_der(const char *label, const void *data, size_t data_len)
{
    printf("Print HEX for DER output TBD\n");
    //test_output_memory(label, data, data_len);
}

static void dump_pem(const char *label, const void *data, size_t data_len)
{
    printf("Print string for PEM output TBD\n");
    //test_output_string(label, data, data_len - 1);
}

static int check_unprotected_PKCS8_DER(const char *file, const int line,
                                       const char *type,
                                       const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    PKCS8_PRIV_KEY_INFO *p8inf =
        d2i_PKCS8_PRIV_KEY_INFO(NULL, &datap, data_len);
    int ok = 0;

    if (TEST_FL_ptr(p8inf)) {
        EVP_PKEY *pkey = EVP_PKCS82PKEY_ex(p8inf, testctx, testpropq);
        char *namelist = NULL;

        if (TEST_FL_ptr(pkey)) {
            if (!(ok = TEST_FL_true(EVP_PKEY_is_a(pkey, type)))) {
                EVP_PKEY_type_names_do_all(pkey, collect_name, &namelist);
                if (namelist != NULL)
                    TEST_note("%s isn't any of %s", type, namelist);
                OPENSSL_free(namelist);
            }
            ok = ok && TEST_FL_true(evp_pkey_is_provided(pkey));
            EVP_PKEY_free(pkey);
        }
    }
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return ok;
}

static int test_unprotected_via_DER(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key,
                              OSSL_KEYMGMT_SELECT_KEYPAIR
                              | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
                              "DER", "PrivateKeyInfo", NULL, NULL,
                              encode_EVP_PKEY_prov, decode_EVP_PKEY_prov,
                              test_mem, check_unprotected_PKCS8_DER,
                              dump_der, 0);
}

static int check_unprotected_PKCS8_PEM(const char *file, const int line,
                                       const char *type,
                                       const void *data, size_t data_len)
{
    static const char expected_pem_header[] =
        "-----BEGIN " PEM_STRING_PKCS8INF "-----";

    return TEST_FL_strn_eq(data, expected_pem_header,
                        sizeof(expected_pem_header) - 1);
}

static int test_unprotected_via_PEM(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key,
                              OSSL_KEYMGMT_SELECT_KEYPAIR
                              | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
                              "PEM", "PrivateKeyInfo", NULL, NULL,
                              encode_EVP_PKEY_prov, decode_EVP_PKEY_prov,
                              test_text, check_unprotected_PKCS8_PEM,
                              dump_pem, 0);
}

#ifndef OPENSSL_NO_KEYPARAMS
static int check_params_DER(const char *file, const int line,
                            const char *type, const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    int ok = 0;
    int itype = NID_undef;
    EVP_PKEY *pkey = NULL;

    if (strcmp(type, "DH") == 0)
        itype = EVP_PKEY_DH;
    else if (strcmp(type, "X9.42 DH") == 0)
        itype = EVP_PKEY_DHX;
    else if (strcmp(type, "DSA") ==  0)
        itype = EVP_PKEY_DSA;
    else if (strcmp(type, "EC") ==  0)
        itype = EVP_PKEY_EC;

    if (itype != NID_undef) {
        pkey = d2i_KeyParams(itype, NULL, &datap, data_len);
        ok = (pkey != NULL);
        EVP_PKEY_free(pkey);
    }

    return ok;
}

static int check_params_PEM(const char *file, const int line,
                            const char *type,
                            const void *data, size_t data_len)
{
    static char expected_pem_header[80];

    return
        TEST_FL_int_gt(BIO_snprintf(expected_pem_header,
                                 sizeof(expected_pem_header),
                                 "-----BEGIN %s PARAMETERS-----", type), 0)
        && TEST_FL_strn_eq(data, expected_pem_header, strlen(expected_pem_header));
}

static int test_params_via_DER(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                              "DER", "type-specific", NULL, NULL,
                              encode_EVP_PKEY_prov, decode_EVP_PKEY_prov,
                              test_mem, check_params_DER,
                              dump_der, FLAG_DECODE_WITH_TYPE);
}

static int test_params_via_PEM(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                              "PEM", "type-specific", NULL, NULL,
                              encode_EVP_PKEY_prov, decode_EVP_PKEY_prov,
                              test_text, check_params_PEM,
                              dump_pem, 0);
}
#endif /* !OPENSSL_NO_KEYPARAMS */

static int check_unprotected_legacy_PEM(const char *file, const int line,
                                        const char *type,
                                        const void *data, size_t data_len)
{
    static char expected_pem_header[80];

    return
        TEST_FL_int_gt(BIO_snprintf(expected_pem_header,
                                 sizeof(expected_pem_header),
                                 "-----BEGIN %s PRIVATE KEY-----", type), 0)
        && TEST_FL_strn_eq(data, expected_pem_header, strlen(expected_pem_header));
}

static int check_MSBLOB(const char *file, const int line,
                        const char *type, const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    EVP_PKEY *pkey = b2i_PrivateKey(&datap, data_len);
    int ok = TEST_FL_ptr(pkey);

    EVP_PKEY_free(pkey);
    return ok;
}

static int test_unprotected_via_MSBLOB(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key,
                              OSSL_KEYMGMT_SELECT_KEYPAIR
                              | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                              "MSBLOB", NULL, NULL, NULL,
                              encode_EVP_PKEY_MSBLOB, decode_EVP_PKEY_prov,
                              test_mem, check_MSBLOB,
                              dump_der, 0);
}

/* stolen from openssl/crypto/pem/pvkfmt.c as ossl_do_PVK_header not public API: */
/* The PVK file magic number: seems to spell out "bobsfile", who is Bob? */
# define MS_PVKMAGIC             0xb0b5f11eL
/* Salt length for PVK files */
# define PVK_SALTLEN             0x10
/* Maximum length in PVK header */
# define PVK_MAX_KEYLEN          102400
/* Maximum salt length */
# define PVK_MAX_SALTLEN         10240

static unsigned int read_ledword(const unsigned char **in)
{
    const unsigned char *p = *in;
    unsigned int ret;

    ret = (unsigned int)*p++;
    ret |= (unsigned int)*p++ << 8;
    ret |= (unsigned int)*p++ << 16;
    ret |= (unsigned int)*p++ << 24;
    *in = p;
    return ret;
}

static int oqsx_do_PVK_header(const unsigned char **in, unsigned int length,
                       int skip_magic,
                       unsigned int *psaltlen, unsigned int *pkeylen)
{
    const unsigned char *p = *in;
    unsigned int pvk_magic, is_encrypted;

    if (skip_magic) {
        if (length < 20) {
            ERR_raise(ERR_LIB_PEM, PEM_R_PVK_TOO_SHORT);
            return 0;
        }
    } else {
        if (length < 24) {
            ERR_raise(ERR_LIB_PEM, PEM_R_PVK_TOO_SHORT);
            return 0;
        }
        pvk_magic = read_ledword(&p);
        if (pvk_magic != MS_PVKMAGIC) {
            ERR_raise(ERR_LIB_PEM, PEM_R_BAD_MAGIC_NUMBER);
            return 0;
        }
    }
    /* Skip reserved */
    p += 4;
    /*
     * keytype =
     */ read_ledword(&p);
    is_encrypted = read_ledword(&p);
    *psaltlen = read_ledword(&p);
    *pkeylen = read_ledword(&p);

    if (*pkeylen > PVK_MAX_KEYLEN || *psaltlen > PVK_MAX_SALTLEN)
        return 0;

    if (is_encrypted && *psaltlen == 0) {
        ERR_raise(ERR_LIB_PEM, PEM_R_INCONSISTENT_HEADER);
        return 0;
    }

    *in = p;
    return 1;
}

/* end steal */

static int check_PVK(const char *file, const int line,
                     const char *type, const void *data, size_t data_len)
{
    const unsigned char *in = data;
    unsigned int saltlen = 0, keylen = 0;
    int ok = oqsx_do_PVK_header(&in, data_len, 0, &saltlen, &keylen);

    return ok;
}

static int test_unprotected_via_PVK(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key,
                              OSSL_KEYMGMT_SELECT_KEYPAIR
                              | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                              "PVK", NULL, NULL, NULL,
                              encode_EVP_PKEY_PVK, decode_EVP_PKEY_prov,
                              test_mem, check_PVK,
                              dump_der, 0);
}

static const char *pass_cipher = "AES-256-CBC";
static const char *pass = "the holy handgrenade of antioch";

static int check_protected_PKCS8_DER(const char *file, const int line,
                                     const char *type,
                                     const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    X509_SIG *p8 = d2i_X509_SIG(NULL, &datap, data_len);
    int ok = TEST_FL_ptr(p8);

    X509_SIG_free(p8);
    return ok;
}

static int test_protected_via_DER(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key,
                              OSSL_KEYMGMT_SELECT_KEYPAIR
                              | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                              "DER", "EncryptedPrivateKeyInfo", pass, pass_cipher,
                              encode_EVP_PKEY_prov, decode_EVP_PKEY_prov,
                              test_mem, check_protected_PKCS8_DER,
                              dump_der, 0);
}

static int check_protected_PKCS8_PEM(const char *file, const int line,
                                     const char *type,
                                     const void *data, size_t data_len)
{
    static const char expected_pem_header[] =
        "-----BEGIN " PEM_STRING_PKCS8 "-----";

    return TEST_FL_strn_eq(data, expected_pem_header,
                        sizeof(expected_pem_header) - 1);
}

static int test_protected_via_PEM(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key,
                              OSSL_KEYMGMT_SELECT_KEYPAIR
                              | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                              "PEM", "EncryptedPrivateKeyInfo", pass, pass_cipher,
                              encode_EVP_PKEY_prov, decode_EVP_PKEY_prov,
                              test_text, check_protected_PKCS8_PEM,
                              dump_pem, 0);
}

static int check_public_DER(const char *file, const int line,
                            const char *type, const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    EVP_PKEY *pkey = d2i_PUBKEY_ex(NULL, &datap, data_len, testctx, testpropq);
    int ok = (TEST_FL_ptr(pkey) && TEST_FL_true(EVP_PKEY_is_a(pkey, type)));

    EVP_PKEY_free(pkey);
    return ok;
}

static int test_public_via_DER(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key,
                              OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                              | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
                              "DER", "SubjectPublicKeyInfo", NULL, NULL,
                              encode_EVP_PKEY_prov, decode_EVP_PKEY_prov,
                              test_mem, check_public_DER, dump_der, 0);
}

static int check_public_PEM(const char *file, const int line,
                            const char *type, const void *data, size_t data_len)
{
    static const char expected_pem_header[] =
        "-----BEGIN " PEM_STRING_PUBLIC "-----";

    return
        TEST_FL_strn_eq(data, expected_pem_header,
                     sizeof(expected_pem_header) - 1);
}

static int test_public_via_PEM(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key,
                              OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                              | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
                              "PEM", "SubjectPublicKeyInfo", NULL, NULL,
                              encode_EVP_PKEY_prov, decode_EVP_PKEY_prov,
                              test_text, check_public_PEM, dump_pem, 0);
}

static int check_public_MSBLOB(const char *file, const int line,
                               const char *type,
                               const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    EVP_PKEY *pkey = b2i_PublicKey(&datap, data_len);
    int ok = TEST_FL_ptr(pkey);

    EVP_PKEY_free(pkey);
    return ok;
}

static int test_public_via_MSBLOB(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(__FILE__, __LINE__, type, key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                              | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                              "MSBLOB", NULL, NULL, NULL,
                              encode_EVP_PKEY_MSBLOB, decode_EVP_PKEY_prov,
                              test_mem, check_public_MSBLOB, dump_der, 0);
}

#define KEYS(KEYTYPE)                           \
    static EVP_PKEY *key_##KEYTYPE = NULL
// disabled retval test to permit NULL retval for unsupported algorithms:
#define MAKE_KEYS(KEYTYPE, KEYTYPEstr, params)                          \
        key_##KEYTYPE = oqstest_make_key(KEYTYPEstr, NULL, params)
#define FREE_KEYS(KEYTYPE)                                              \
    EVP_PKEY_free(key_##KEYTYPE);                                       \

#define DOMAIN_KEYS(KEYTYPE)                    \
    static EVP_PKEY *template_##KEYTYPE = NULL; \
    static EVP_PKEY *key_##KEYTYPE = NULL
#define MAKE_DOMAIN_KEYS(KEYTYPE, KEYTYPEstr, params)                   \
    ok = ok                                                             \
        && TEST_ptr(template_##KEYTYPE =                                \
                    oqstest_make_template(KEYTYPEstr, params))          \
        && TEST_ptr(key_##KEYTYPE =                                     \
                    oqstest_make_key(KEYTYPEstr, template_##KEYTYPE, NULL))
#define FREE_DOMAIN_KEYS(KEYTYPE)                                       \
    EVP_PKEY_free(template_##KEYTYPE);                                  \
    EVP_PKEY_free(key_##KEYTYPE)

#define IMPLEMENT_TEST_SUITE(KEYTYPE, KEYTYPEstr)                       \
    static int test_unprotected_##KEYTYPE##_via_DER(void)               \
    {                                                                   \
        return test_unprotected_via_DER(KEYTYPEstr, key_##KEYTYPE);     \
    }                                                                   \
    static int test_unprotected_##KEYTYPE##_via_PEM(void)               \
    {                                                                   \
        return test_unprotected_via_PEM(KEYTYPEstr, key_##KEYTYPE);     \
    }                                                                   \
    static int test_public_##KEYTYPE##_via_DER(void)                    \
    {                                                                   \
        return test_public_via_DER(KEYTYPEstr, key_##KEYTYPE);          \
    }                                                                   \
    static int test_protected_##KEYTYPE##_via_DER(void)                 \
    {                                                                   \
        return test_protected_via_DER(KEYTYPEstr, key_##KEYTYPE);       \
    }                                                                   \
    static int test_protected_##KEYTYPE##_via_PEM(void)                 \
    {                                                                   \
        return test_protected_via_PEM(KEYTYPEstr, key_##KEYTYPE);       \
    }                                                                   \
    static int test_public_##KEYTYPE##_via_PEM(void)                    \
    {                                                                   \
        return test_public_via_PEM(KEYTYPEstr, key_##KEYTYPE);          \
    }                                                                   

#define ADD_TEST_SUITE(KEYTYPE)                                 \
    ADD_TEST(test_unprotected_##KEYTYPE##_via_DER);             \
    ADD_TEST(test_unprotected_##KEYTYPE##_via_PEM);             \
    ADD_TEST(test_public_##KEYTYPE##_via_DER);                  \
    ADD_TEST(test_protected_##KEYTYPE##_via_DER);               \
    ADD_TEST(test_protected_##KEYTYPE##_via_PEM);               \
    ADD_TEST(test_public_##KEYTYPE##_via_PEM)

#define IMPLEMENT_TEST_SUITE_PARAMS(KEYTYPE, KEYTYPEstr)           \
    static int test_params_##KEYTYPE##_via_DER(void)               \
    {                                                              \
        return test_params_via_DER(KEYTYPEstr, key_##KEYTYPE);     \
    }                                                              \
    static int test_params_##KEYTYPE##_via_PEM(void)               \
    {                                                              \
        return test_params_via_PEM(KEYTYPEstr, key_##KEYTYPE);     \
    }

#define ADD_TEST_SUITE_PARAMS(KEYTYPE)                          \
    ADD_TEST(test_params_##KEYTYPE##_via_DER);                  \
    ADD_TEST(test_params_##KEYTYPE##_via_PEM)

#define IMPLEMENT_TEST_SUITE_MSBLOB(KEYTYPE, KEYTYPEstr)                \
    static int test_unprotected_##KEYTYPE##_via_MSBLOB(void)            \
    {                                                                   \
        return test_unprotected_via_MSBLOB(KEYTYPEstr, key_##KEYTYPE);  \
    }                                                                   \
    static int test_public_##KEYTYPE##_via_MSBLOB(void)                 \
    {                                                                   \
        return test_public_via_MSBLOB(KEYTYPEstr, key_##KEYTYPE);       \
    }

#define ADD_TEST_SUITE_MSBLOB(KEYTYPE)                                  \
    ADD_TEST(test_unprotected_##KEYTYPE##_via_MSBLOB);                  \
    ADD_TEST(test_public_##KEYTYPE##_via_MSBLOB)

#define IMPLEMENT_TEST_SUITE_UNPROTECTED_PVK(KEYTYPE, KEYTYPEstr)       \
    static int test_unprotected_##KEYTYPE##_via_PVK(void)               \
    {                                                                   \
        return test_unprotected_via_PVK(KEYTYPEstr, key_##KEYTYPE);     \
    }
# define ADD_TEST_SUITE_UNPROTECTED_PVK(KEYTYPE)                        \
    ADD_TEST(test_unprotected_##KEYTYPE##_via_PVK)
#ifndef OPENSSL_NO_RC4
# define IMPLEMENT_TEST_SUITE_PROTECTED_PVK(KEYTYPE, KEYTYPEstr)        \
    static int test_protected_##KEYTYPE##_via_PVK(void)                 \
    {                                                                   \
        return test_protected_via_PVK(KEYTYPEstr, key_##KEYTYPE);       \
    }
# define ADD_TEST_SUITE_PROTECTED_PVK(KEYTYPE)                          \
    ADD_TEST(test_protected_##KEYTYPE##_via_PVK)
#endif

///// OQS_TEMPLATE_FRAGMENT_IMPLEMENT_START
KEYS(dilithium2);
IMPLEMENT_TEST_SUITE(dilithium2, "dilithium2")
KEYS(p256_dilithium2);
IMPLEMENT_TEST_SUITE(p256_dilithium2, "p256_dilithium2")
KEYS(rsa3072_dilithium2);
IMPLEMENT_TEST_SUITE(rsa3072_dilithium2, "rsa3072_dilithium2")
KEYS(dilithium3);
IMPLEMENT_TEST_SUITE(dilithium3, "dilithium3")
KEYS(p384_dilithium3);
IMPLEMENT_TEST_SUITE(p384_dilithium3, "p384_dilithium3")
KEYS(dilithium5);
IMPLEMENT_TEST_SUITE(dilithium5, "dilithium5")
KEYS(p521_dilithium5);
IMPLEMENT_TEST_SUITE(p521_dilithium5, "p521_dilithium5")
KEYS(dilithium2_aes);
IMPLEMENT_TEST_SUITE(dilithium2_aes, "dilithium2_aes")
KEYS(p256_dilithium2_aes);
IMPLEMENT_TEST_SUITE(p256_dilithium2_aes, "p256_dilithium2_aes")
KEYS(rsa3072_dilithium2_aes);
IMPLEMENT_TEST_SUITE(rsa3072_dilithium2_aes, "rsa3072_dilithium2_aes")
KEYS(dilithium3_aes);
IMPLEMENT_TEST_SUITE(dilithium3_aes, "dilithium3_aes")
KEYS(p384_dilithium3_aes);
IMPLEMENT_TEST_SUITE(p384_dilithium3_aes, "p384_dilithium3_aes")
KEYS(dilithium5_aes);
IMPLEMENT_TEST_SUITE(dilithium5_aes, "dilithium5_aes")
KEYS(p521_dilithium5_aes);
IMPLEMENT_TEST_SUITE(p521_dilithium5_aes, "p521_dilithium5_aes")
KEYS(falcon512);
IMPLEMENT_TEST_SUITE(falcon512, "falcon512")
KEYS(p256_falcon512);
IMPLEMENT_TEST_SUITE(p256_falcon512, "p256_falcon512")
KEYS(rsa3072_falcon512);
IMPLEMENT_TEST_SUITE(rsa3072_falcon512, "rsa3072_falcon512")
KEYS(falcon1024);
IMPLEMENT_TEST_SUITE(falcon1024, "falcon1024")
KEYS(p521_falcon1024);
IMPLEMENT_TEST_SUITE(p521_falcon1024, "p521_falcon1024")
KEYS(picnicl1full);
IMPLEMENT_TEST_SUITE(picnicl1full, "picnicl1full")
KEYS(p256_picnicl1full);
IMPLEMENT_TEST_SUITE(p256_picnicl1full, "p256_picnicl1full")
KEYS(rsa3072_picnicl1full);
IMPLEMENT_TEST_SUITE(rsa3072_picnicl1full, "rsa3072_picnicl1full")
KEYS(picnic3l1);
IMPLEMENT_TEST_SUITE(picnic3l1, "picnic3l1")
KEYS(p256_picnic3l1);
IMPLEMENT_TEST_SUITE(p256_picnic3l1, "p256_picnic3l1")
KEYS(rsa3072_picnic3l1);
IMPLEMENT_TEST_SUITE(rsa3072_picnic3l1, "rsa3072_picnic3l1")
KEYS(rainbowVclassic);
IMPLEMENT_TEST_SUITE(rainbowVclassic, "rainbowVclassic")
KEYS(p521_rainbowVclassic);
IMPLEMENT_TEST_SUITE(p521_rainbowVclassic, "p521_rainbowVclassic")
KEYS(sphincsharaka128frobust);
IMPLEMENT_TEST_SUITE(sphincsharaka128frobust, "sphincsharaka128frobust")
KEYS(p256_sphincsharaka128frobust);
IMPLEMENT_TEST_SUITE(p256_sphincsharaka128frobust, "p256_sphincsharaka128frobust")
KEYS(rsa3072_sphincsharaka128frobust);
IMPLEMENT_TEST_SUITE(rsa3072_sphincsharaka128frobust, "rsa3072_sphincsharaka128frobust")
KEYS(sphincssha256128frobust);
IMPLEMENT_TEST_SUITE(sphincssha256128frobust, "sphincssha256128frobust")
KEYS(p256_sphincssha256128frobust);
IMPLEMENT_TEST_SUITE(p256_sphincssha256128frobust, "p256_sphincssha256128frobust")
KEYS(rsa3072_sphincssha256128frobust);
IMPLEMENT_TEST_SUITE(rsa3072_sphincssha256128frobust, "rsa3072_sphincssha256128frobust")
KEYS(sphincsshake256128frobust);
IMPLEMENT_TEST_SUITE(sphincsshake256128frobust, "sphincsshake256128frobust")
KEYS(p256_sphincsshake256128frobust);
IMPLEMENT_TEST_SUITE(p256_sphincsshake256128frobust, "p256_sphincsshake256128frobust")
KEYS(rsa3072_sphincsshake256128frobust);
IMPLEMENT_TEST_SUITE(rsa3072_sphincsshake256128frobust, "rsa3072_sphincsshake256128frobust")
///// OQS_TEMPLATE_FRAGMENT_IMPLEMENT_END

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONTEXT,
    OPT_TRACE_ENCODER,
    OPT_TRACE_DECODER,
    OPT_CONFIG_FILE,
    OPT_PROVIDER_NAME,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "context", OPT_CONTEXT, '-',
          "Explicitly use a non-default library context" },
        { "trace-encoder", OPT_TRACE_ENCODER, '-',
          "Enable full encoder tracing" },
        { "trace-decoder", OPT_TRACE_DECODER, '-',
          "Enable full decoder tracing" },
        { "config", OPT_CONFIG_FILE, '<',
          "The configuration file to use for the library context" },
        { "provider", OPT_PROVIDER_NAME, 's',
          "The provider to load (The default value is 'default')" },
        { NULL }
    };
    return options;
}

int setup_tests(void)
{
    const char *prov_name = "oqsprovider";
    char *config_file = NULL;
    int ok = 1;
    BIO *err = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);

    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_CONTEXT:
            default_libctx = 0;
            break;
        case OPT_TRACE_ENCODER:
            OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_ENCODER, err);
            break;
        case OPT_TRACE_DECODER:
            OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_DECODER, err);
            break;
        case OPT_PROVIDER_NAME:
            prov_name = opt_arg();
            break;
        case OPT_CONFIG_FILE:
            config_file = opt_arg();
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    if (default_libctx) {
        if (!test_get_libctx(NULL, NULL, config_file, &oqsprov, prov_name))
            return 0;
    } else {
        if (!test_get_libctx(&testctx, NULL, config_file, &oqsprov, prov_name))
            return 0;
    }

    /* Separate provider/ctx for generating the test data */
    if (!TEST_ptr(keyctx = OSSL_LIB_CTX_new()))
        return 0;
    // Enabling DRBG via default provider, both for key and default context
    if (!TEST_ptr(dfltprov = OSSL_PROVIDER_load(NULL, "default")))
        return 0;
    if (!TEST_ptr(dfltprov = OSSL_PROVIDER_load(keyctx, "default")))
        return 0;
    if (!TEST_ptr(keyprov = OSSL_PROVIDER_load(keyctx, prov_name)))
        return 0;

    TEST_info("Generating keys...");

///// OQS_TEMPLATE_FRAGMENT_ADD_START
    MAKE_KEYS(dilithium2, "dilithium2", NULL);
    ADD_TEST_SUITE(dilithium2);
    MAKE_KEYS(p256_dilithium2, "p256_dilithium2", NULL);
    ADD_TEST_SUITE(p256_dilithium2);
    MAKE_KEYS(rsa3072_dilithium2, "rsa3072_dilithium2", NULL);
    ADD_TEST_SUITE(rsa3072_dilithium2);
    MAKE_KEYS(dilithium3, "dilithium3", NULL);
    ADD_TEST_SUITE(dilithium3);
    MAKE_KEYS(p384_dilithium3, "p384_dilithium3", NULL);
    ADD_TEST_SUITE(p384_dilithium3);
    MAKE_KEYS(dilithium5, "dilithium5", NULL);
    ADD_TEST_SUITE(dilithium5);
    MAKE_KEYS(p521_dilithium5, "p521_dilithium5", NULL);
    ADD_TEST_SUITE(p521_dilithium5);
    MAKE_KEYS(dilithium2_aes, "dilithium2_aes", NULL);
    ADD_TEST_SUITE(dilithium2_aes);
    MAKE_KEYS(p256_dilithium2_aes, "p256_dilithium2_aes", NULL);
    ADD_TEST_SUITE(p256_dilithium2_aes);
    MAKE_KEYS(rsa3072_dilithium2_aes, "rsa3072_dilithium2_aes", NULL);
    ADD_TEST_SUITE(rsa3072_dilithium2_aes);
    MAKE_KEYS(dilithium3_aes, "dilithium3_aes", NULL);
    ADD_TEST_SUITE(dilithium3_aes);
    MAKE_KEYS(p384_dilithium3_aes, "p384_dilithium3_aes", NULL);
    ADD_TEST_SUITE(p384_dilithium3_aes);
    MAKE_KEYS(dilithium5_aes, "dilithium5_aes", NULL);
    ADD_TEST_SUITE(dilithium5_aes);
    MAKE_KEYS(p521_dilithium5_aes, "p521_dilithium5_aes", NULL);
    ADD_TEST_SUITE(p521_dilithium5_aes);
    MAKE_KEYS(falcon512, "falcon512", NULL);
    ADD_TEST_SUITE(falcon512);
    MAKE_KEYS(p256_falcon512, "p256_falcon512", NULL);
    ADD_TEST_SUITE(p256_falcon512);
    MAKE_KEYS(rsa3072_falcon512, "rsa3072_falcon512", NULL);
    ADD_TEST_SUITE(rsa3072_falcon512);
    MAKE_KEYS(falcon1024, "falcon1024", NULL);
    ADD_TEST_SUITE(falcon1024);
    MAKE_KEYS(p521_falcon1024, "p521_falcon1024", NULL);
    ADD_TEST_SUITE(p521_falcon1024);
    MAKE_KEYS(picnicl1full, "picnicl1full", NULL);
    ADD_TEST_SUITE(picnicl1full);
    MAKE_KEYS(p256_picnicl1full, "p256_picnicl1full", NULL);
    ADD_TEST_SUITE(p256_picnicl1full);
    MAKE_KEYS(rsa3072_picnicl1full, "rsa3072_picnicl1full", NULL);
    ADD_TEST_SUITE(rsa3072_picnicl1full);
    MAKE_KEYS(picnic3l1, "picnic3l1", NULL);
    ADD_TEST_SUITE(picnic3l1);
    MAKE_KEYS(p256_picnic3l1, "p256_picnic3l1", NULL);
    ADD_TEST_SUITE(p256_picnic3l1);
    MAKE_KEYS(rsa3072_picnic3l1, "rsa3072_picnic3l1", NULL);
    ADD_TEST_SUITE(rsa3072_picnic3l1);
    MAKE_KEYS(rainbowVclassic, "rainbowVclassic", NULL);
    ADD_TEST_SUITE(rainbowVclassic);
    MAKE_KEYS(p521_rainbowVclassic, "p521_rainbowVclassic", NULL);
    ADD_TEST_SUITE(p521_rainbowVclassic);
    MAKE_KEYS(sphincsharaka128frobust, "sphincsharaka128frobust", NULL);
    ADD_TEST_SUITE(sphincsharaka128frobust);
    MAKE_KEYS(p256_sphincsharaka128frobust, "p256_sphincsharaka128frobust", NULL);
    ADD_TEST_SUITE(p256_sphincsharaka128frobust);
    MAKE_KEYS(rsa3072_sphincsharaka128frobust, "rsa3072_sphincsharaka128frobust", NULL);
    ADD_TEST_SUITE(rsa3072_sphincsharaka128frobust);
    MAKE_KEYS(sphincssha256128frobust, "sphincssha256128frobust", NULL);
    ADD_TEST_SUITE(sphincssha256128frobust);
    MAKE_KEYS(p256_sphincssha256128frobust, "p256_sphincssha256128frobust", NULL);
    ADD_TEST_SUITE(p256_sphincssha256128frobust);
    MAKE_KEYS(rsa3072_sphincssha256128frobust, "rsa3072_sphincssha256128frobust", NULL);
    ADD_TEST_SUITE(rsa3072_sphincssha256128frobust);
    MAKE_KEYS(sphincsshake256128frobust, "sphincsshake256128frobust", NULL);
    ADD_TEST_SUITE(sphincsshake256128frobust);
    MAKE_KEYS(p256_sphincsshake256128frobust, "p256_sphincsshake256128frobust", NULL);
    ADD_TEST_SUITE(p256_sphincsshake256128frobust);
    MAKE_KEYS(rsa3072_sphincsshake256128frobust, "rsa3072_sphincsshake256128frobust", NULL);
    ADD_TEST_SUITE(rsa3072_sphincsshake256128frobust);
///// OQS_TEMPLATE_FRAGMENT_ADD_END

    return 1;
}

void cleanup_tests(void)
{
///// OQS_TEMPLATE_FRAGMENT_FREEKEYS_START
    FREE_KEYS(dilithium2);
    FREE_KEYS(p256_dilithium2);
    FREE_KEYS(rsa3072_dilithium2);
    FREE_KEYS(dilithium3);
    FREE_KEYS(p384_dilithium3);
    FREE_KEYS(dilithium5);
    FREE_KEYS(p521_dilithium5);
    FREE_KEYS(dilithium2_aes);
    FREE_KEYS(p256_dilithium2_aes);
    FREE_KEYS(rsa3072_dilithium2_aes);
    FREE_KEYS(dilithium3_aes);
    FREE_KEYS(p384_dilithium3_aes);
    FREE_KEYS(dilithium5_aes);
    FREE_KEYS(p521_dilithium5_aes);
    FREE_KEYS(falcon512);
    FREE_KEYS(p256_falcon512);
    FREE_KEYS(rsa3072_falcon512);
    FREE_KEYS(falcon1024);
    FREE_KEYS(p521_falcon1024);
    FREE_KEYS(picnicl1full);
    FREE_KEYS(p256_picnicl1full);
    FREE_KEYS(rsa3072_picnicl1full);
    FREE_KEYS(picnic3l1);
    FREE_KEYS(p256_picnic3l1);
    FREE_KEYS(rsa3072_picnic3l1);
    FREE_KEYS(rainbowVclassic);
    FREE_KEYS(p521_rainbowVclassic);
    FREE_KEYS(sphincsharaka128frobust);
    FREE_KEYS(p256_sphincsharaka128frobust);
    FREE_KEYS(rsa3072_sphincsharaka128frobust);
    FREE_KEYS(sphincssha256128frobust);
    FREE_KEYS(p256_sphincssha256128frobust);
    FREE_KEYS(rsa3072_sphincssha256128frobust);
    FREE_KEYS(sphincsshake256128frobust);
    FREE_KEYS(p256_sphincsshake256128frobust);
    FREE_KEYS(rsa3072_sphincsshake256128frobust);
///// OQS_TEMPLATE_FRAGMENT_FREEKEYS_END

    OSSL_PROVIDER_unload(dfltprov);
    OSSL_PROVIDER_unload(oqsprov);
    OSSL_PROVIDER_unload(keyprov);
    OSSL_LIB_CTX_free(testctx);
    OSSL_LIB_CTX_free(keyctx);
}

