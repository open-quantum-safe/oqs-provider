/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL rsa kem.
 * 
 * TBC: OQS license
 *
 * ToDo: Adding hybrid alg support; More testing with more key types.
 */

/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include "e_os.h"  /* strcasecmp */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <crypto/rsa.h>
#include "prov/providercommonerr.h"
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/securitycheck.h"
#include "prov/oqsx.h"

// debugging
#define OQS_KEM_PRINTF(a) if (getenv("OQSKEM")) printf(a)
#define OQS_KEM_PRINTF2(a, b) if (getenv("OQSKEM")) printf(a, b)
#define OQS_KEM_PRINTF3(a, b, c) if (getenv("OQSKEM")) printf(a, b, c)


static OSSL_FUNC_kem_newctx_fn oqs_kem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn oqs_kem_encaps_init;
static OSSL_FUNC_kem_encapsulate_fn oqs_kem_encaps;
static OSSL_FUNC_kem_decapsulate_init_fn oqs_kem_decaps_init;
static OSSL_FUNC_kem_decapsulate_fn oqs_kem_decaps;
static OSSL_FUNC_kem_freectx_fn oqs_kem_freectx;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    OQSX_KEY *kem;
} PROV_OQSKEM_CTX;

static void *oqs_kem_newctx(void *provctx)
{
    PROV_OQSKEM_CTX *pkemctx =  OPENSSL_zalloc(sizeof(PROV_OQSKEM_CTX));

    OQS_KEM_PRINTF("OQS KEM provider called: newctx\n");
    if (pkemctx == NULL)
        return NULL;
    pkemctx->libctx = PROV_LIBCTX_OF(provctx);
    // kem will only be set in init

    return pkemctx;
}

static void oqs_kem_freectx(void *vpkemctx)
{
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;

    OQS_KEM_PRINTF("OQS KEM provider called: freectx\n");
    oqsx_key_free(pkemctx->kem);
    OPENSSL_free(pkemctx);
}

static int oqs_kem_decapsencaps_init(void *vpkemctx, void *vkem, int operation)
{
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;

    OQS_KEM_PRINTF3("OQS KEM provider called: _init : New: %p; old: %p \n", vkem, pkemctx->kem);
    if (pkemctx == NULL || vkem == NULL || !oqsx_key_up_ref(vkem)) 
        return 0;
    oqsx_key_free(pkemctx->kem);
    pkemctx->kem = vkem;

    return 1;
}

static int oqs_kem_encaps_init(void *vpkemctx, void *vkem)
{
    OQS_KEM_PRINTF("OQS KEM provider called: encaps_init\n");
    return oqs_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_ENCAPSULATE);
}

static int oqs_kem_decaps_init(void *vpkemctx, void *vkem)
{
    OQS_KEM_PRINTF("OQS KEM provider called: decaps_init\n");
    return oqs_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_DECAPSULATE);
}

static int oqs_kem_encaps(void *vpkemctx, unsigned char *out, size_t *outlen,
                           unsigned char *secret, size_t *secretlen)
{
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;

    OQS_KEM_PRINTF("OQS KEM provider called: encaps\n");
    if (pkemctx->kem == NULL) {
        printf("OQS Warning: OQS_KEM not initialized\n");
        return -1;
    }
    *outlen = pkemctx->kem->key.k->length_ciphertext;
    *secretlen = pkemctx->kem->key.k->length_shared_secret;
    if (out == NULL || secret == NULL) {
       OQS_KEM_PRINTF3("KEM returning lengths %ld and %ld\n", *outlen, *secretlen);
       return 1;
    }
    return OQS_SUCCESS == OQS_KEM_encaps(pkemctx->kem->key.k, out, secret, pkemctx->kem->pubkey);
}

static int oqs_kem_decaps(void *vpkemctx, unsigned char *out, size_t *outlen,
                          const unsigned char *in, size_t inlen)
{
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;

    OQS_KEM_PRINTF("OQS KEM provider called: decaps\n");
    if (pkemctx->kem == NULL) {
        printf("OQS Warning: OQS_KEM not initialized\n");
        return -1;
    }
    *outlen = pkemctx->kem->key.k->length_shared_secret;
    if (out == NULL) return 1;

    return OQS_SUCCESS == OQS_KEM_decaps(pkemctx->kem->key.k, out, in, pkemctx->kem->privkey);
}

#define MAKE_KEM_FUNCTIONS(alg) \
    const OSSL_DISPATCH oqs_##alg##_kem_functions[] = { \
      { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))oqs_kem_newctx }, \
      { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))oqs_kem_encaps_init }, \
      { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))oqs_kem_encaps }, \
      { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))oqs_kem_decaps_init }, \
      { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))oqs_kem_decaps }, \
      { OSSL_FUNC_KEM_FREECTX, (void (*)(void))oqs_kem_freectx }, \
      { 0, NULL } \
  };

// keep this just in case we need to become ALG-specific at some point in time
MAKE_KEM_FUNCTIONS(generic)
