// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL rsa kem.
 *
 * ToDo: Adding hybrid alg support; More testing with more key types.
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <string.h>
#include <time.h>

#include "oqs_prov.h"

#ifdef NDEBUG
#define OQS_KEM_PRINTF(a)
#define OQS_KEM_PRINTF2(a, b)
#define OQS_KEM_PRINTF3(a, b, c)
#else
#define OQS_KEM_PRINTF(a)                                                      \
    if (getenv("OQSKEM"))                                                      \
    printf(a)
#define OQS_KEM_PRINTF2(a, b)                                                  \
    if (getenv("OQSKEM"))                                                      \
    printf(a, b)
#define OQS_KEM_PRINTF3(a, b, c)                                               \
    if (getenv("OQSKEM"))                                                      \
    printf(a, b, c)
#endif // NDEBUG

static OSSL_FUNC_kem_newctx_fn oqs_kem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn oqs_kem_encaps_init;
static OSSL_FUNC_kem_encapsulate_fn oqs_qs_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn oqs_qs_kem_decaps;
static OSSL_FUNC_kem_freectx_fn oqs_kem_freectx;

enum oqsx_kdf_type_en { KDF_SHA3_256, KDF_SHA256 };

typedef enum oqsx_kdf_type_en OQSX_KDF_TYPE;

struct oqsx_cmp_kem_info_st {
    const char *name;
    const unsigned char domSep[13];
    OQSX_KDF_TYPE kdf;
};

typedef struct oqsx_cmp_kem_info_st OQSX_CMP_KEM_INFO;

#define NUM_CMP_KEM_ALGS 9

const OQSX_CMP_KEM_INFO CMP_KEM_INFO[NUM_CMP_KEM_ALGS] = {
    {"mlkem768_rsa2048",
     {0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x05, 0x02,
      0x15},
     KDF_SHA256},
    {"mlkem768_rsa3072",
     {0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x05, 0x02,
      0x16},
     KDF_SHA256},
    {"mlkem768_rsa4096",
     {0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x05, 0x02,
      0x17},
     KDF_SHA256},
    {"mlkem768_x25519",
     {0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x05, 0x02,
      0x1A},
     KDF_SHA3_256},
    {"mlkem768_p384",
     {0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x05, 0x02,
      0x18},
     KDF_SHA256},
    {"mlkem768_bp256",
     {0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x05, 0x02,
      0x19},
     KDF_SHA256},
    {"mlkem1024_p384",
     {0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x05, 0x02,
      0x1B},
     KDF_SHA3_256},
    {"mlkem1024_bp384",
     {0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x05, 0x02,
      0x1C},
     KDF_SHA3_256},
    {"mlkem1024_x448",
     {0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x05, 0x02,
      0x1D},
     KDF_SHA3_256},
};

DECLARE_ASN1_FUNCTIONS(CompositeCiphertext)

ASN1_NDEF_SEQUENCE(CompositeCiphertext) =
    {
        ASN1_SIMPLE(CompositeCiphertext, ct1, ASN1_OCTET_STRING),
        ASN1_SIMPLE(CompositeCiphertext, ct2, ASN1_OCTET_STRING),
} ASN1_NDEF_SEQUENCE_END(CompositeCiphertext)

        IMPLEMENT_ASN1_FUNCTIONS(CompositeCiphertext)

    /*
     * What's passed as an actual key is defined by the KEYMGMT interface.
     */
    typedef struct {
    OSSL_LIB_CTX *libctx;
    OQSX_KEY *kem;
} PROV_OQSKEM_CTX;

/// Common KEM functions

static void *oqs_kem_newctx(void *provctx) {
    PROV_OQSKEM_CTX *pkemctx = OPENSSL_zalloc(sizeof(PROV_OQSKEM_CTX));

    OQS_KEM_PRINTF("OQS KEM provider called: newctx\n");
    if (pkemctx == NULL)
        return NULL;
    pkemctx->libctx = PROV_OQS_LIBCTX_OF(provctx);
    // kem will only be set in init

    return pkemctx;
}

static void oqs_kem_freectx(void *vpkemctx) {
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;

    OQS_KEM_PRINTF("OQS KEM provider called: freectx\n");
    oqsx_key_free(pkemctx->kem);
    OPENSSL_free(pkemctx);
}

static int oqs_kem_decapsencaps_init(void *vpkemctx, void *vkem,
                                     int operation) {
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;

    OQS_KEM_PRINTF3("OQS KEM provider called: _init : New: %p; old: %p \n",
                    vkem, pkemctx->kem);
    if (pkemctx == NULL || vkem == NULL || !oqsx_key_up_ref(vkem))
        return 0;
    oqsx_key_free(pkemctx->kem);
    pkemctx->kem = vkem;

    return 1;
}

static int oqs_kem_encaps_init(void *vpkemctx, void *vkem,
                               const OSSL_PARAM params[]) {
    OQS_KEM_PRINTF("OQS KEM provider called: encaps_init\n");
    return oqs_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_ENCAPSULATE);
}

static int oqs_kem_decaps_init(void *vpkemctx, void *vkem,
                               const OSSL_PARAM params[]) {
    OQS_KEM_PRINTF("OQS KEM provider called: decaps_init\n");
    return oqs_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_DECAPSULATE);
}

static int oqs_kem_combiner(const PROV_OQSKEM_CTX *pkemctx,
                            const unsigned char *tradSS, size_t tradSSLen,
                            const unsigned char *mlkemSS, size_t mlkemSSLen,
                            const unsigned char *tradCT, size_t tradCTLen,
                            const unsigned char *tradPK, size_t tradPKLen,
                            unsigned char *output, size_t *outputLen) {
    int ret = 1, ret2 = 0;

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4], *p = params;

    unsigned char *buf = NULL, *b = NULL;
    const size_t bufLen = mlkemSSLen + tradSSLen + tradCTLen + tradPKLen;

    const OQSX_CMP_KEM_INFO *info = NULL;
    const unsigned char counter[4] = {0x00, 0x00, 0x00, 0x01};
    const size_t hashLen = 256;
    const unsigned char salt[256] = {0};

    *outputLen = hashLen;

    if (tradSS == NULL || mlkemSS == NULL || tradCT == NULL || tradPK == NULL ||
        output == NULL) {
        ON_ERR_SET_GOTO(1, ret, 1, err);
    }

    for (int i = 0; i < NUM_CMP_KEM_ALGS; i++) {
        if (strcmp(CMP_KEM_INFO[i].name, pkemctx->kem->tls_name) == 0) {
            info = &CMP_KEM_INFO[i];
            break;
        }
    }
    ON_ERR_SET_GOTO(info == NULL, ret, 0, err);

    switch (info->kdf) {
    case KDF_SHA3_256:
        kdf = EVP_KDF_fetch(NULL, "SSKDF", NULL);
        ON_ERR_SET_GOTO(!kdf, ret, 0, err_kdf);
        kctx = EVP_KDF_CTX_new(kdf);
        ON_ERR_SET_GOTO(!kctx, ret, 0, err_kctx);

        *p++ = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST, SN_sha3_256, strlen(SN_sha3_256));

        break;
    case KDF_SHA256:
        kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
        ON_ERR_SET_GOTO(!kdf, ret, 0, err_kdf);
        kctx = EVP_KDF_CTX_new(kdf);
        ON_ERR_SET_GOTO(!kctx, ret, 0, err_kctx);

        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                SN_sha256, strlen(SN_sha256));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                 (void *)salt, hashLen);

        break;
    default:
        ON_ERR_SET_GOTO(1, ret, 0, err);
    }

    buf = OPENSSL_malloc(bufLen);
    ON_ERR_SET_GOTO(!buf, ret, 0, err_buf);
    b = buf;

    memcpy(b, mlkemSS, mlkemSSLen);
    b += mlkemSSLen;
    memcpy(b, tradSS, tradSSLen);
    b += tradSSLen;
    memcpy(b, tradCT, tradCTLen);
    b += tradCTLen;
    memcpy(b, tradPK, tradPKLen);
    b += tradPKLen;

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)buf,
                                             bufLen);
    *p = OSSL_PARAM_construct_end();

    ret2 = EVP_KDF_derive(kctx, output, *outputLen, params);
    ON_ERR_SET_GOTO(ret2 != 1, ret, 0, err_kctx);

err_kctx:
    EVP_KDF_CTX_free(kctx);
err_kdf:
    EVP_KDF_free(kdf);
err_buf:
    OPENSSL_clear_free(buf, bufLen);
err:
    return ret;
}

/// Quantum-Safe KEM functions (OQS)

static int oqs_qs_kem_encaps_keyslot(void *vpkemctx, unsigned char *out,
                                     size_t *outlen, unsigned char *secret,
                                     size_t *secretlen, int keyslot) {
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQS_KEM *kem_ctx = NULL;

    OQS_KEM_PRINTF("OQS KEM provider called: encaps\n");
    if (pkemctx->kem == NULL) {
        OQS_KEM_PRINTF("OQS Warning: OQS_KEM not initialized\n");
        return -1;
    }

    kem_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;
    if (pkemctx->kem->comp_pubkey == NULL ||
        pkemctx->kem->comp_pubkey[keyslot] == NULL) {
        OQS_KEM_PRINTF("OQS Warning: public key is NULL\n");
        return -1;
    }
    if (outlen == NULL) {
        OQS_KEM_PRINTF("OQS Warning: outlen is NULL\n");
        return -1;
    }
    if (secretlen == NULL) {
        OQS_KEM_PRINTF("OQS Warning: secretlen is NULL\n");
        return -1;
    }
    if (out == NULL || secret == NULL) {
        *outlen = kem_ctx->length_ciphertext;
        *secretlen = kem_ctx->length_shared_secret;
        OQS_KEM_PRINTF3("KEM returning lengths %ld and %ld\n",
                        kem_ctx->length_ciphertext,
                        kem_ctx->length_shared_secret);
        return 1;
    }

    if (*outlen < kem_ctx->length_ciphertext) {
        OQS_KEM_PRINTF("OQS Warning: out buffer too small\n");
        return -1;
    }
    if (*secretlen < kem_ctx->length_shared_secret) {
        OQS_KEM_PRINTF("OQS Warning: secret buffer too small\n");
        return -1;
    }
    *outlen = kem_ctx->length_ciphertext;
    *secretlen = kem_ctx->length_shared_secret;

    return OQS_SUCCESS == OQS_KEM_encaps(kem_ctx, out, secret,
                                         pkemctx->kem->comp_pubkey[keyslot]);
}

static int oqs_qs_kem_decaps_keyslot(void *vpkemctx, unsigned char *out,
                                     size_t *outlen, const unsigned char *in,
                                     size_t inlen, int keyslot) {
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQS_KEM *kem_ctx = NULL;

    OQS_KEM_PRINTF("OQS KEM provider called: decaps\n");
    if (pkemctx->kem == NULL) {
        OQS_KEM_PRINTF("OQS Warning: OQS_KEM not initialized\n");
        return -1;
    }
    kem_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;
    if (pkemctx->kem->comp_privkey == NULL ||
        pkemctx->kem->comp_privkey[keyslot] == NULL) {
        OQS_KEM_PRINTF("OQS Warning: private key is NULL\n");
        return -1;
    }
    if (out == NULL) {
        if (outlen != NULL) {
            *outlen = kem_ctx->length_shared_secret;
        }
        OQS_KEM_PRINTF2("KEM returning length %ld\n",
                        kem_ctx->length_shared_secret);
        return 1;
    }
    if (inlen != kem_ctx->length_ciphertext) {
        OQS_KEM_PRINTF("OQS Warning: wrong input length\n");
        return 0;
    }
    if (in == NULL) {
        OQS_KEM_PRINTF("OQS Warning: in is NULL\n");
        return -1;
    }
    if (outlen == NULL) {
        OQS_KEM_PRINTF("OQS Warning: outlen is NULL\n");
        return -1;
    }
    if (*outlen < kem_ctx->length_shared_secret) {
        OQS_KEM_PRINTF("OQS Warning: out buffer too small\n");
        return -1;
    }
    *outlen = kem_ctx->length_shared_secret;

    return OQS_SUCCESS == OQS_KEM_decaps(kem_ctx, out, in,
                                         pkemctx->kem->comp_privkey[keyslot]);
}

static int oqs_qs_kem_encaps(void *vpkemctx, unsigned char *out, size_t *outlen,
                             unsigned char *secret, size_t *secretlen) {
    return oqs_qs_kem_encaps_keyslot(vpkemctx, out, outlen, secret, secretlen,
                                     0);
}

static int oqs_qs_kem_decaps(void *vpkemctx, unsigned char *out, size_t *outlen,
                             const unsigned char *in, size_t inlen) {
    return oqs_qs_kem_decaps_keyslot(vpkemctx, out, outlen, in, inlen, 0);
}

#include "oqs_hyb_kem.c"

#define MAKE_KEM_FUNCTIONS(alg)                                                \
    const OSSL_DISPATCH oqs_##alg##_kem_functions[] = {                        \
        {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))oqs_kem_newctx},                \
        {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))oqs_kem_encaps_init}, \
        {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))oqs_qs_kem_encaps},        \
        {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))oqs_kem_decaps_init}, \
        {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))oqs_qs_kem_decaps},        \
        {OSSL_FUNC_KEM_FREECTX, (void (*)(void))oqs_kem_freectx},              \
        {0, NULL}};

#define MAKE_HYB_KEM_FUNCTIONS(alg)                                            \
    const OSSL_DISPATCH oqs_##alg##_kem_functions[] = {                        \
        {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))oqs_kem_newctx},                \
        {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))oqs_kem_encaps_init}, \
        {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))oqs_hyb_kem_encaps},       \
        {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))oqs_kem_decaps_init}, \
        {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))oqs_hyb_kem_decaps},       \
        {OSSL_FUNC_KEM_FREECTX, (void (*)(void))oqs_kem_freectx},              \
        {0, NULL}};

#define MAKE_CMP_KEM_FUNCTIONS(alg)                                            \
    const OSSL_DISPATCH oqs_##alg##_kem_functions[] = {                        \
        {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))oqs_kem_newctx},                \
        {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))oqs_kem_encaps_init}, \
        {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))oqs_cmp_kem_encaps},       \
        {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))oqs_kem_decaps_init}, \
        {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))oqs_cmp_kem_decaps},       \
        {OSSL_FUNC_KEM_FREECTX, (void (*)(void))oqs_kem_freectx},              \
        {0, NULL}};

// keep this just in case we need to become ALG-specific at some point in time
MAKE_KEM_FUNCTIONS(generic)
MAKE_HYB_KEM_FUNCTIONS(hybrid)
MAKE_CMP_KEM_FUNCTIONS(composite)
