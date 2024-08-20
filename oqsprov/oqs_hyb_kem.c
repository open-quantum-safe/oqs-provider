// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Hybrid KEM code.
 *
 */

static OSSL_FUNC_kem_encapsulate_fn oqs_hyb_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn oqs_hyb_kem_decaps;

/// EVP KEM functions

static int oqs_evp_kem_encaps_keyslot(void *vpkemctx, unsigned char *ct,
                                      size_t *ctlen, unsigned char *secret,
                                      size_t *secretlen, int keyslot) {
    int ret = OQS_SUCCESS, ret2 = 0;

    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQSX_EVP_CTX *evp_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_evp_ctx;

    size_t pubkey_kexlen = 0;
    size_t kexDeriveLen = 0, pkeylen = 0;
    unsigned char *pubkey_kex = pkemctx->kem->comp_pubkey[keyslot];

    // Free at err:
    EVP_PKEY_CTX *ctx = NULL, *kgctx = NULL;
    ;
    EVP_PKEY *pkey = NULL, *peerpk = NULL;
    unsigned char *ctkex_encoded = NULL;

    pubkey_kexlen = evp_ctx->evp_info->length_public_key;
    kexDeriveLen = evp_ctx->evp_info->kex_length_secret;

    *ctlen = pubkey_kexlen;
    *secretlen = kexDeriveLen;

    if (ct == NULL || secret == NULL) {
        OQS_KEM_PRINTF3("EVP KEM returning lengths %ld and %ld\n", *ctlen,
                        *secretlen);
        return 1;
    }

    peerpk = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!peerpk, ret, -1, err);

    ret2 = EVP_PKEY_copy_parameters(peerpk, evp_ctx->keyParam);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, err);

    ret2 = EVP_PKEY_set1_encoded_public_key(peerpk, pubkey_kex, pubkey_kexlen);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, err);

    kgctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
    ON_ERR_SET_GOTO(!kgctx, ret, -1, err);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 != 1, ret, -1, err);

    ret2 = EVP_PKEY_keygen(kgctx, &pkey);
    ON_ERR_SET_GOTO(ret2 != 1, ret, -1, err);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ON_ERR_SET_GOTO(!ctx, ret, -1, err);

    ret = EVP_PKEY_derive_init(ctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    ret = EVP_PKEY_derive_set_peer(ctx, peerpk);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    ret = EVP_PKEY_derive(ctx, secret, &kexDeriveLen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    pkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &ctkex_encoded);
    ON_ERR_SET_GOTO(pkeylen <= 0 || !ctkex_encoded || pkeylen != pubkey_kexlen,
                    ret, -1, err);

    memcpy(ct, ctkex_encoded, pkeylen);

err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerpk);
    OPENSSL_free(ctkex_encoded);
    return ret;
}

static int oqs_evp_kem_decaps_keyslot(void *vpkemctx, unsigned char *secret,
                                      size_t *secretlen,
                                      const unsigned char *ct, size_t ctlen,
                                      int keyslot) {
    OQS_KEM_PRINTF("OQS KEM provider called: oqs_hyb_kem_decaps\n");

    int ret = OQS_SUCCESS, ret2 = 0;
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQSX_EVP_CTX *evp_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_evp_ctx;

    size_t pubkey_kexlen = evp_ctx->evp_info->length_public_key;
    size_t kexDeriveLen = evp_ctx->evp_info->kex_length_secret;
    unsigned char *privkey_kex = pkemctx->kem->comp_privkey[keyslot];
    size_t privkey_kexlen = evp_ctx->evp_info->length_private_key;

    // Free at err:
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL, *peerpkey = NULL;

    *secretlen = kexDeriveLen;
    if (secret == NULL)
        return 1;

    if (evp_ctx->evp_info->raw_key_support) {
        pkey = EVP_PKEY_new_raw_private_key(evp_ctx->evp_info->keytype, NULL,
                                            privkey_kex, privkey_kexlen);
        ON_ERR_SET_GOTO(!pkey, ret, -10, err);
    } else {
        pkey = d2i_AutoPrivateKey(&pkey, (const unsigned char **)&privkey_kex,
                                  privkey_kexlen);
        ON_ERR_SET_GOTO(!pkey, ret, -2, err);
    }

    peerpkey = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!peerpkey, ret, -3, err);

    ret2 = EVP_PKEY_copy_parameters(peerpkey, evp_ctx->keyParam);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -4, err);

    ret2 = EVP_PKEY_set1_encoded_public_key(peerpkey, ct, pubkey_kexlen);
    ON_ERR_SET_GOTO(ret2 <= 0 || !peerpkey, ret, -5, err);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ON_ERR_SET_GOTO(!ctx, ret, -6, err);

    ret = EVP_PKEY_derive_init(ctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -7, err);
    ret = EVP_PKEY_derive_set_peer(ctx, peerpkey);
    ON_ERR_SET_GOTO(ret <= 0, ret, -8, err);

    ret = EVP_PKEY_derive(ctx, secret, &kexDeriveLen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -9, err);

err:
    EVP_PKEY_free(peerpkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/// Hybrid KEM functions

static int oqs_hyb_kem_encaps(void *vpkemctx, unsigned char *ct, size_t *ctlen,
                              unsigned char *secret, size_t *secretlen) {
    int ret = OQS_SUCCESS;
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    size_t secretLen0 = 0, secretLen1 = 0;
    size_t ctLen0 = 0, ctLen1 = 0;
    unsigned char *ct0, *ct1, *secret0, *secret1;

    ret = oqs_evp_kem_encaps_keyslot(vpkemctx, NULL, &ctLen0, NULL, &secretLen0,
                                     0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret = oqs_qs_kem_encaps_keyslot(vpkemctx, NULL, &ctLen1, NULL, &secretLen1,
                                    1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    *ctlen = ctLen0 + ctLen1;
    *secretlen = secretLen0 + secretLen1;

    if (ct == NULL || secret == NULL) {
        OQS_KEM_PRINTF3("HYB KEM returning lengths %ld and %ld\n", *ctlen,
                        *secretlen);
        return 1;
    }

    ct0 = ct;
    ct1 = ct + ctLen0;
    secret0 = secret;
    secret1 = secret + secretLen0;

    ret = oqs_evp_kem_encaps_keyslot(vpkemctx, ct0, &ctLen0, secret0,
                                     &secretLen0, 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    ret = oqs_qs_kem_encaps_keyslot(vpkemctx, ct1, &ctLen1, secret1,
                                    &secretLen1, 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

err:
    return ret;
}

static int oqs_hyb_kem_decaps(void *vpkemctx, unsigned char *secret,
                              size_t *secretlen, const unsigned char *ct,
                              size_t ctlen) {
    int ret = OQS_SUCCESS;
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQSX_EVP_CTX *evp_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_evp_ctx;
    const OQS_KEM *qs_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;

    size_t secretLen0 = 0, secretLen1 = 0;
    size_t ctLen0 = 0, ctLen1 = 0;
    const unsigned char *ct0, *ct1;
    unsigned char *secret0, *secret1;

    ret = oqs_evp_kem_decaps_keyslot(vpkemctx, NULL, &secretLen0, NULL, 0, 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret = oqs_qs_kem_decaps_keyslot(vpkemctx, NULL, &secretLen1, NULL, 0, 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    *secretlen = secretLen0 + secretLen1;

    if (secret == NULL)
        return 1;

    ctLen0 = evp_ctx->evp_info->length_public_key;
    ctLen1 = qs_ctx->length_ciphertext;

    ON_ERR_SET_GOTO(ctLen0 + ctLen1 != ctlen, ret, OQS_ERROR, err);

    ct0 = ct;
    ct1 = ct + ctLen0;
    secret0 = secret;
    secret1 = secret + secretLen0;

    ret = oqs_evp_kem_decaps_keyslot(vpkemctx, secret0, &secretLen0, ct0,
                                     ctLen0, 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret = oqs_qs_kem_decaps_keyslot(vpkemctx, secret1, &secretLen1, ct1, ctLen1,
                                    1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

err:
    return ret;
}
