// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL rsa kem.
 *
 * Hybrid KEM
 *
 * Message/ciphertext encoding follows https://tools.ietf.org/html/draft-ietf-tls-hybrid-design-01
 */

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include "oqsx.h"
#include <string.h>

#ifdef NDEBUG
#define OQS_HYBKEM_PRINTF(a)
#define OQS_HYBKEM_PRINTF2(a, b)
#define OQS_HYBKEM_PRINTF3(a, b, c)
#else
#define OQS_HYBKEM_PRINTF(a) if (getenv("OQSHYBKEM")) printf(a)
#define OQS_HYBKEM_PRINTF2(a, b) if (getenv("OQSHYBKEM")) printf(a, b)
#define OQS_HYBKEM_PRINTF3(a, b, c) if (getenv("OQSHYBKEM")) printf(a, b, c)
#endif // NDEBUG


static OSSL_FUNC_kem_newctx_fn oqs_hyb_kem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn oqs_hyb_kem_encaps_init;
static OSSL_FUNC_kem_encapsulate_fn oqs_hyb_kem_encaps;
static OSSL_FUNC_kem_decapsulate_init_fn oqs_hyb_kem_decaps_init;
static OSSL_FUNC_kem_decapsulate_fn oqs_hyb_kem_decaps;
static OSSL_FUNC_kem_freectx_fn oqs_hyb_kem_freectx;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    OQSX_KEY *kem;
} PROV_OQSHYBKEM_CTX;

static void get_pubkey_ptr(unsigned char *pubkey,
                           unsigned char **pubkey_kem,
                           size_t *pubkey_kemlen,
                           unsigned char **pubkey_kex,
                           size_t *pubkey_kexlen)
{
    DECODE_UINT32(*pubkey_kemlen, pubkey);
    DECODE_UINT32(*pubkey_kexlen, pubkey + 4 + *pubkey_kemlen);

    *pubkey_kem = pubkey + 4;
    *pubkey_kex = pubkey + 4 + *pubkey_kemlen + 4;
}

static void get_privkey_ptr(unsigned char *privkey,
                            unsigned char **privkey_kem,
                            size_t *privkey_kemlen,
                            unsigned char **privkey_kex,
                            size_t *privkey_kexlen)
{
    DECODE_UINT32(*privkey_kemlen, privkey);
    DECODE_UINT32(*privkey_kexlen, privkey + 4 + *privkey_kemlen);

    *privkey_kem = privkey + 4;
    *privkey_kex = privkey + 4 + *privkey_kemlen + 4;
}

/* Gets the pointers to two messages/ciphertexts (classical and PQC):
   Expected format: ct1 || ct2
   Follows format specified in https://tools.ietf.org/html/draft-stebila-tls-hybrid-design-03
 */
static int get_ct_ptr(const unsigned char *ct, uint16_t ctlen,
                      unsigned char **ct1, uint16_t ct1len,
                      unsigned char **ct2, uint16_t ct2len)
{
    int ret = 1;
    int index = 0;

    ON_ERR_SET_GOTO(ctlen != ct1len + ct2len, ret, 0, err);
    ON_ERR_SET_GOTO(!ct, ret, 0, err);

    *ct1 = (unsigned char *) ct + index;
    index += ct1len;
    *ct2 = (unsigned char *) ct + index;

    err:
    return ret;
}

static OQS_HYB_KEM *get_hyb_kem(const PROV_OQSHYBKEM_CTX *pkemctx)
{
    return (OQS_HYB_KEM *)pkemctx->kem->primitive.hybkem;
}

static void *oqs_hyb_kem_newctx(void *provctx)
{
    PROV_OQSHYBKEM_CTX *pkemctx =  OPENSSL_zalloc(sizeof(PROV_OQSHYBKEM_CTX));


    OQS_HYBKEM_PRINTF("OQS Hybrid KEM provider called: newctx\n");
    if (pkemctx == NULL)
        return NULL;
    pkemctx->libctx = PROV_OQS_LIBCTX_OF(provctx);
    // kem will only be set in init

    return pkemctx;
}

static void oqs_hyb_kem_freectx(void *vpkemctx)
{
    PROV_OQSHYBKEM_CTX *pkemctx = (PROV_OQSHYBKEM_CTX *)vpkemctx;

    OQS_HYBKEM_PRINTF("OQS Hybrid KEM provider called: freectx\n");
    oqsx_key_free(pkemctx->kem);
    OPENSSL_free(pkemctx);
}

static int oqs_hyb_kem_decapsencaps_init(void *vpkemctx, void *vkem, int operation)
{
    PROV_OQSHYBKEM_CTX *pkemctx = (PROV_OQSHYBKEM_CTX *)vpkemctx;

    OQS_HYBKEM_PRINTF3("OQS Hybrid KEM provider called: _init : New: %p; old: %p \n", vkem, pkemctx->kem);
    if (pkemctx == NULL || vkem == NULL || !oqsx_key_up_ref(vkem))
        return 0;
    oqsx_key_free(pkemctx->kem);
    pkemctx->kem = vkem;

    return 1;
}

static int oqs_hyb_kem_encaps_init(void *vpkemctx, void *vkem, const OSSL_PARAM params[])
{
    OQS_HYBKEM_PRINTF("OQS Hybrid KEM provider called: encaps_init\n");
    return oqs_hyb_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_ENCAPSULATE);
}

static int oqs_hyb_kem_decaps_init(void *vpkemctx, void *vkem, const OSSL_PARAM params[])
{
    OQS_HYBKEM_PRINTF("OQS Hybrid KEM provider called: decaps_init\n");
    return oqs_hyb_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_DECAPSULATE);
}

#if 0
static void printhex(const char* title, unsigned char* c, size_t clen) {
    printf("%s = ", title);
    for (int i = 0; i < clen; ++i) {
        printf("%02x", c[i]);
    }
    printf("\n");
}
static void print_ss(const char* title, unsigned char *ss1, size_t ss1len, unsigned char *ss2, size_t ss2len)
{
    printf("%s ..\n", title);
    printhex("ss1", ss1, ss1len);
    printhex("ss2", ss2, ss2len);
    fflush(stdout);
}
#endif

static int oqs_hyb_kem_encaps(void *vpkemctx, unsigned char *ct, size_t *ctlen,
                          unsigned char *secret, size_t *secretlen)
{
    int ret = OQS_SUCCESS, ret2 = 0;

    PROV_OQSHYBKEM_CTX *pkemctx = (PROV_OQSHYBKEM_CTX *)vpkemctx;
    unsigned char *pubkey_kem = NULL, *pubkey_kex = NULL;
    unsigned char *ct1 = NULL, *ct2 = NULL;
    size_t pubkey_kemlen = 0, pubkey_kexlen = 0;
    size_t kexDeriveLen = 0, pkeylen = 0;
    OQS_HYB_KEM *hybkem = get_hyb_kem(pkemctx);
    EVP_PKEY_CTX *kctx = hybkem->kex;
    EVP_PKEY_CTX *pctx, *ctx;
    EVP_PKEY *pkey = NULL, *peerpk = NULL;

    OQS_HYBKEM_PRINTF("OQS Hybrid KEM provider called: encaps\n");
    get_pubkey_ptr(pkemctx->kem->pubkey, &pubkey_kem, &pubkey_kemlen, &pubkey_kex, &pubkey_kexlen);

    kexDeriveLen = (size_t) EVP_PKEY_size(hybkem->kexParam);
    ON_ERR_GOTO(kexDeriveLen <= 0, err);
    OQS_HYBKEM_PRINTF2("kexDeriveLen = %zu\n", kexDeriveLen);


    *ctlen = hybkem->kem->length_ciphertext + pubkey_kexlen;
    *secretlen = hybkem->kem->length_shared_secret + kexDeriveLen;

    if (ct == NULL || secret == NULL) {
        OQS_HYBKEM_PRINTF3("KEM returning lengths %ld and %ld\n", *ctlen, *secretlen);
        return 1;
    }

    peerpk = EVP_PKEY_new_raw_public_key(hybkem->kex_nid, NULL, pubkey_kex, pubkey_kexlen);
    ON_ERR_SET_GOTO(!peerpk, ret, -1, err);

    ret2 = EVP_PKEY_keygen_init(kctx);
    ON_ERR_SET_GOTO(ret2 != 1, ret, -1, err);
    ret2 = EVP_PKEY_keygen(kctx, &pkey);
    ON_ERR_SET_GOTO(ret2 != 1, ret, -1, err);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ON_ERR_SET_GOTO(!ctx, ret, -1, err);

    ret = EVP_PKEY_derive_init(ctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);
    ret = EVP_PKEY_derive_set_peer(ctx, peerpk);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    get_ct_ptr(ct, *ctlen, &ct1, hybkem->kem->length_ciphertext, &ct2, pubkey_kexlen);

    ret = EVP_PKEY_derive(ctx, secret + hybkem->kem->length_shared_secret, &kexDeriveLen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    ret = OQS_SUCCESS == OQS_KEM_encaps(hybkem->kem, ct1, secret, pubkey_kem);
    ON_ERR_SET_GOTO(!ret, ret, -1, err);

    // Note: this EVP API works only with x25519 and x448
    ret = EVP_PKEY_get_raw_public_key(pkey, NULL, &pkeylen);
    ON_ERR_SET_GOTO(ret <= 0 || pkeylen != pubkey_kexlen, ret, -1, err);

    ret = EVP_PKEY_get_raw_public_key(pkey, ct2, &pkeylen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

err:
    return ret;
}

static int oqs_hyb_kem_decaps(void *vpkemctx, unsigned char *secret, size_t *secretlen,
                          const unsigned char *ct, size_t ctlen)
{
    OQS_HYBKEM_PRINTF("OQS Hybrid KEM provider called: decaps\n");

    int ret = OQS_SUCCESS, ret2 = 0;
    PROV_OQSHYBKEM_CTX *pkemctx = (PROV_OQSHYBKEM_CTX *)vpkemctx;
    ON_ERR_GOTO(!pkemctx->kem, err);

    OQS_HYB_KEM *hybkem = get_hyb_kem(pkemctx);
    EVP_PKEY_CTX *kctx = hybkem->kex;
    OQS_KEM *kemctx = hybkem->kem;
    EVP_PKEY_CTX *pctx, *ctx;
    EVP_PKEY *pkey = NULL, *peerpkey = NULL;
    unsigned char *ct1 = NULL, *ct2 = NULL;
    size_t pubkey_kexlen = ctlen - hybkem->kem->length_ciphertext;
    size_t kexDeriveLen = (size_t) EVP_PKEY_size(hybkem->kexParam);
    unsigned char *privkey_kem = NULL, *privkey_kex = NULL;
    size_t privkey_kemlen = 0, privkey_kexlen = 0;

    get_privkey_ptr(pkemctx->kem->privkey, &privkey_kem, &privkey_kemlen, &privkey_kex, &privkey_kexlen);

    *secretlen = hybkem->kem->length_shared_secret + kexDeriveLen;
    if (secret == NULL) return 1;

    pkey = EVP_PKEY_new_raw_private_key(hybkem->kex_nid, NULL, privkey_kex, privkey_kexlen);
    ON_ERR_SET_GOTO(!pkey, ret, -1, err);

    get_ct_ptr(ct, ctlen, &ct1, hybkem->kem->length_ciphertext, &ct2, pubkey_kexlen);

    peerpkey = EVP_PKEY_new_raw_public_key(hybkem->kex_nid, NULL, ct2, pubkey_kexlen);
    ON_ERR_SET_GOTO(!peerpkey, ret, -1, err);


    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ON_ERR_SET_GOTO(!ctx, ret, -1, err);

    ret = EVP_PKEY_derive_init(ctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);
    ret = EVP_PKEY_derive_set_peer(ctx, peerpkey);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    ret = EVP_PKEY_derive(ctx, secret + kemctx->length_shared_secret, &kexDeriveLen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    ret = OQS_SUCCESS == OQS_KEM_decaps(kemctx, secret, ct1, privkey_kem);

err:
    return ret;
}

#define MAKE_HYB_KEM_FUNCTIONS(alg) \
    const OSSL_DISPATCH oqs_##alg##_kem_functions[] = { \
      { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))oqs_hyb_kem_newctx }, \
      { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))oqs_hyb_kem_encaps_init }, \
      { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))oqs_hyb_kem_encaps }, \
      { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))oqs_hyb_kem_decaps_init }, \
      { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))oqs_hyb_kem_decaps }, \
      { OSSL_FUNC_KEM_FREECTX, (void (*)(void))oqs_hyb_kem_freectx }, \
      { 0, NULL } \
  };

// keep this just in case we need to become ALG-specific at some point in time
MAKE_HYB_KEM_FUNCTIONS(hybrid)
