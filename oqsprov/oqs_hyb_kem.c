// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Hybrid KEM code.
 *
 */

#include "oqs_prov.h"
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/types.h>
#include <string.h>
static OSSL_FUNC_kem_encapsulate_fn oqs_hyb_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn oqs_hyb_kem_decaps;

/// EVP KEM functions

static int oqs_evp_kem_encaps_keyslot(void *vpkemctx, unsigned char *ct,
                                      size_t *ctlen, unsigned char *secret,
                                      size_t *secretlen, int keyslot) {
    int ret = OQS_SUCCESS, ret2 = 0;

    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQSX_EVP_CTX *evp_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_evp_ctx;
    const int keytype = evp_ctx->evp_info->keytype;

    size_t pubkey_kexlen = 0;
    size_t kexDeriveLen = 0, pkeylen = 0, outlen = 0;
    unsigned char *pubkey_kex = pkemctx->kem->comp_pubkey[keyslot];

    // Free at err:
    EVP_PKEY_CTX *ctx = NULL, *kgctx = NULL;

    EVP_PKEY *pkey = NULL, *peerpk = NULL;
    unsigned char *ctkex_encoded = NULL;

    pubkey_kexlen = evp_ctx->evp_info->length_public_key;
    kexDeriveLen = evp_ctx->evp_info->kex_length_secret;

    if (keytype == EVP_PKEY_RSA) {
        // *ctlen = evp_ctx->evp_info->kex_length_secret;
        *secretlen = (size_t)32;

        pkey = d2i_PublicKey(keytype, NULL, (const unsigned char **)&pubkey_kex,
                             pubkey_kexlen);
        ON_ERR_SET_GOTO(!pkey, ret, -1, err);

        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        ON_ERR_SET_GOTO(!ctx, ret, -1, err);

        ret = EVP_PKEY_encrypt_init(ctx);
        ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

        ret = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

        ret = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
        ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

        ret = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
        ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

        // set pSourceFunc to empty string for pSpecifiedEmptyIdentifier
        // passing NULL as label breaks on OpenSSL 3.0.0 pass "" instead
        const char *empty = "";
        char *label = OPENSSL_malloc(1);
        strcpy(label, empty);
        ret = EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, (void *)label, 0);
        ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

        ret = EVP_PKEY_encrypt(ctx, NULL, ctlen, NULL, *secretlen);
        ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

        if (ct == NULL || secret == NULL) {
            OQS_KEM_PRINTF3("EVP KEM returning lengths %ld and %ld\n", *ctlen,
                            *secretlen);
            ret = 1;
            goto err;
        }

        // generate random secret, 256 bits = 32 bytes
        if (RAND_priv_bytes(secret, *secretlen) <= 0) {
            ret = -1;
            goto err;
        }

        // outlen = kexDeriveLen;
        ret = EVP_PKEY_encrypt(ctx, ct, ctlen, secret, *secretlen);
        ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    } else {
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

        ret2 =
            EVP_PKEY_set1_encoded_public_key(peerpk, pubkey_kex, pubkey_kexlen);
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
        ON_ERR_SET_GOTO(pkeylen <= 0 || !ctkex_encoded ||
                            pkeylen != pubkey_kexlen,
                        ret, -1, err);

        memcpy(ct, ctkex_encoded, pkeylen);
    }

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
    const int keytype = evp_ctx->evp_info->keytype;

    size_t pubkey_kexlen = evp_ctx->evp_info->length_public_key;
    size_t kexDeriveLen = evp_ctx->evp_info->kex_length_secret;
    unsigned char *privkey_kex = pkemctx->kem->comp_privkey[keyslot];
    size_t privkey_kexlen = evp_ctx->evp_info->length_private_key;

    // Free at err:
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL, *peerpkey = NULL;

    if (keytype == EVP_PKEY_RSA) {
        *secretlen = 32;
        // size_t outlen = 32; // expected secret length (256 bits)

        pkey =
            d2i_PrivateKey(keytype, NULL, (const unsigned char **)&privkey_kex,
                           privkey_kexlen);
        ON_ERR_SET_GOTO(!pkey, ret, -1, err);

        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        ON_ERR_SET_GOTO(!ctx, ret, -2, err);

        ret = EVP_PKEY_decrypt_init(ctx);
        ON_ERR_SET_GOTO(ret <= 0, ret, -3, err);

        ret = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        ON_ERR_SET_GOTO(ret <= 0, ret, -4, err);

        ret = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
        ON_ERR_SET_GOTO(ret <= 0, ret, -5, err);

        ret = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
        ON_ERR_SET_GOTO(ret <= 0, ret, -6, err);

        // expect pSourceFunc to be pSpecifiedEmptyIdentifier
        // passing NULL as label breaks on OpenSSL 3.0.0 pass "" instead
        const char *empty = "";
        char *label = OPENSSL_malloc(1);
        strcpy(label, empty);
        ret = EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, (void *)label, 0);
        ON_ERR_SET_GOTO(ret <= 0, ret, -7, err);

        ret = EVP_PKEY_decrypt(ctx, NULL, secretlen, NULL, ctlen);
        ON_ERR_SET_GOTO(ret <= 0, ret, -8, err);

        if (secret == NULL) {
            OQS_KEM_PRINTF2("EVP KEM returning lengths %ld\n", *secretlen);
            ret = 1;
            goto err;
        }

        ret = EVP_PKEY_decrypt(ctx, secret, secretlen, ct, ctlen);
        ON_ERR_SET_GOTO(ret <= 0, ret, -8, err);

    } else {
        *secretlen = kexDeriveLen;
        if (secret == NULL) {
            OQS_KEM_PRINTF2("EVP KEM returning lengths %ld\n", *secretlen);
            return 1;
        }

        if (evp_ctx->evp_info->raw_key_support) {
            pkey = EVP_PKEY_new_raw_private_key(
                evp_ctx->evp_info->keytype, NULL, privkey_kex, privkey_kexlen);
            ON_ERR_SET_GOTO(!pkey, ret, -10, err);
        } else {
            pkey = d2i_AutoPrivateKey(
                &pkey, (const unsigned char **)&privkey_kex, privkey_kexlen);
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
    }

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
    const OQSX_KEY *oqsx_key = pkemctx->kem;
    size_t secretLenClassical = 0, secretLenPQ = 0;
    size_t ctLenClassical = 0, ctLenPQ = 0;
    unsigned char *ctClassical, *ctPQ, *secretClassical, *secretPQ;

    ret = oqs_evp_kem_encaps_keyslot(vpkemctx, NULL, &ctLenClassical, NULL,
                                     &secretLenClassical,
                                     oqsx_key->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret =
        oqs_qs_kem_encaps_keyslot(vpkemctx, NULL, &ctLenPQ, NULL, &secretLenPQ,
                                  oqsx_key->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    *ctlen = ctLenClassical + ctLenPQ;
    *secretlen = secretLenClassical + secretLenPQ;

    if (ct == NULL || secret == NULL) {
        OQS_KEM_PRINTF3("HYB KEM returning lengths %ld and %ld\n", *ctlen,
                        *secretlen);
        return 1;
    }

    /* Rule: if the classical algorthm is not FIPS approved
       but the PQ algorithm is: PQ share comes first
       otherwise: classical share comes first
     */
    if (oqsx_key->reverse_share) {
        ctPQ = ct;
        ctClassical = ct + ctLenPQ;
        secretPQ = secret;
        secretClassical = secret + secretLenPQ;
    } else {
        ctClassical = ct;
        ctPQ = ct + ctLenClassical;
        secretClassical = secret;
        secretPQ = secret + secretLenClassical;
    }

    ret = oqs_evp_kem_encaps_keyslot(vpkemctx, ctClassical, &ctLenClassical,
                                     secretClassical, &secretLenClassical,
                                     oqsx_key->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    ret = oqs_qs_kem_encaps_keyslot(vpkemctx, ctPQ, &ctLenPQ, secretPQ,
                                    &secretLenPQ,
                                    oqsx_key->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

err:
    return ret;
}

static int oqs_hyb_kem_decaps(void *vpkemctx, unsigned char *secret,
                              size_t *secretlen, const unsigned char *ct,
                              size_t ctlen) {
    int ret = OQS_SUCCESS;
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQSX_KEY *oqsx_key = pkemctx->kem;
    const OQSX_EVP_CTX *evp_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_evp_ctx;
    const OQS_KEM *qs_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;

    size_t secretLenClassical = 0, secretLenPQ = 0;
    size_t ctLenClassical = 0, ctLenPQ = 0;
    const unsigned char *ctClassical, *ctPQ;
    unsigned char *secretClassical, *secretPQ;

    ret = oqs_evp_kem_decaps_keyslot(vpkemctx, NULL, &secretLenClassical, NULL,
                                     0, oqsx_key->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret = oqs_qs_kem_decaps_keyslot(vpkemctx, NULL, &secretLenPQ, NULL, 0,
                                    oqsx_key->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    *secretlen = secretLenClassical + secretLenPQ;

    if (secret == NULL)
        return 1;

    ctLenClassical = evp_ctx->evp_info->length_public_key;
    ctLenPQ = qs_ctx->length_ciphertext;

    ON_ERR_SET_GOTO(ctLenClassical + ctLenPQ != ctlen, ret, OQS_ERROR, err);

    /* Rule: if the classical algorthm is not FIPS approved
       but the PQ algorithm is: PQ share comes first
       otherwise: classical share comes first
     */
    if (oqsx_key->reverse_share) {
        ctPQ = ct;
        ctClassical = ct + ctLenPQ;
        secretPQ = secret;
        secretClassical = secret + secretLenPQ;
    } else {
        ctClassical = ct;
        ctPQ = ct + ctLenClassical;
        secretClassical = secret;
        secretPQ = secret + secretLenClassical;
    }

    ret = oqs_evp_kem_decaps_keyslot(
        vpkemctx, secretClassical, &secretLenClassical, ctClassical,
        ctLenClassical, oqsx_key->reverse_share ? 1 : 0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret = oqs_qs_kem_decaps_keyslot(vpkemctx, secretPQ, &secretLenPQ, ctPQ,
                                    ctLenPQ, oqsx_key->reverse_share ? 0 : 1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

err:
    return ret;
}

// Composite KEM functions

static int oqs_cmp_kem_encaps(void *vpkemctx, unsigned char *ct, size_t *ctlen,
                              unsigned char *secret, size_t *secretlen) {
    int ret = 1, ret2 = 0;
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQS_KEM *qs_kem = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;
    const OQSX_EVP_INFO *evp_info =
        pkemctx->kem->oqsx_provider_ctx.oqsx_evp_ctx->evp_info;

    size_t secretLen0 = 0, secretLen1 = 0;
    size_t ctLen0 = 0, ctLen1 = 0;
    unsigned char *ct0 = NULL, *ct1 = NULL;
    unsigned char *secret0 = NULL, *secret1 = NULL;

    CompositeCiphertext *cmpCT;
    unsigned char *p = ct; // temp ptr because i2d_* may move input ct ptr

    ret2 = oqs_qs_kem_encaps_keyslot(vpkemctx, NULL, &ctLen0, NULL, &secretLen0,
                                     0);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, 0, err);
    secret0 = OPENSSL_zalloc(secretLen0);
    ON_ERR_SET_GOTO(!secret0, ret, 0, err_secret0);
    ct0 = OPENSSL_zalloc(ctLen0);
    ON_ERR_SET_GOTO(!ct0, ret, 0, err_ct0);

    ret2 = oqs_evp_kem_encaps_keyslot(vpkemctx, NULL, &ctLen1, NULL,
                                      &secretLen1, 1);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, 0, err_ct0);
    secret1 = OPENSSL_zalloc(secretLen1);
    ON_ERR_SET_GOTO(!secret1, ret, 0, err_secret1);
    ct1 = OPENSSL_zalloc(ctLen1);
    ON_ERR_SET_GOTO(!ct1, ret, 0, err_ct1);

    cmpCT = CompositeCiphertext_new();
    ON_ERR_SET_GOTO(!cmpCT, ret, OQS_ERROR, err_cmpct);

    if (ct == NULL || secret == NULL) {
        unsigned char *temp = NULL;

        ret2 = ASN1_STRING_set(cmpCT->ct1, ct0, ctLen0);
        if (!ret2) {
            OPENSSL_free(temp);
            ON_ERR_SET_GOTO(1, ret, 0, err_cmpct);
        }

        ret2 = ASN1_STRING_set(cmpCT->ct2, ct1, ctLen1);
        if (!ret2) {
            OPENSSL_free(temp);
            ON_ERR_SET_GOTO(1, ret, 0, err_cmpct);
        }

        *ctlen = (size_t)i2d_CompositeCiphertext(cmpCT, &temp);
        if (ctlen <= 0) {
            OPENSSL_free(temp);
            ON_ERR_SET_GOTO(1, ret, 0, err_cmpct);
        }

        ret2 = oqs_kem_combiner(
            pkemctx, NULL, secretLen1, NULL, secretLen0, NULL, ctLen1, NULL,
            pkemctx->kem->pubkeylen_cmp[1], NULL, secretlen);
        if (!ret2) {
            OPENSSL_free(temp);
            ON_ERR_SET_GOTO(1, ret, 0, err_cmpct);
        }

        OPENSSL_free(temp);
        ON_ERR_SET_GOTO(1, ret, 1, err_cmpct);
    }

    ret2 = oqs_qs_kem_encaps_keyslot(vpkemctx, ct0, &ctLen0, secret0,
                                     &secretLen0, 0);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, 0, err_cmpct);

    ret2 = oqs_evp_kem_encaps_keyslot(vpkemctx, ct1, &ctLen1, secret1,
                                      &secretLen1, 1);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, 0, err_cmpct);

    ret2 = ASN1_STRING_set(cmpCT->ct1, ct0, ctLen0);
    ON_ERR_SET_GOTO(!ret2, ret, 0, err_cmpct);

    ret2 = ASN1_STRING_set(cmpCT->ct2, ct1, ctLen1);
    ON_ERR_SET_GOTO(!ret2, ret, 0, err_cmpct);

    *ctlen = (size_t)i2d_CompositeCiphertext(cmpCT, &p);
    ON_ERR_SET_GOTO(ctlen <= 0, ret, 0, err_cmpct);

    ret2 = oqs_kem_combiner(pkemctx, secret1, secretLen1, secret0, secretLen0,
                            ct1, ctLen1, pkemctx->kem->comp_pubkey[1],
                            pkemctx->kem->pubkeylen_cmp[1], secret, secretlen);
    ON_ERR_SET_GOTO(!ret2, ret, 0, err_cmpct);

err_cmpct:
    CompositeCiphertext_free(cmpCT);
err_ct1:
    OPENSSL_free(ct1);
err_secret1:
    OPENSSL_clear_free(secret1, secretLen1);
err_ct0:
    OPENSSL_free(ct0);
err_secret0:
    OPENSSL_clear_free(secret0, secretLen0);
err:
    return ret;
}

static int oqs_cmp_kem_decaps(void *vpkemctx, unsigned char *secret,
                              size_t *secretlen, const unsigned char *ct,
                              size_t ctlen) {
    int ret = 1, ret2 = 0;
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQS_KEM *qs_kem = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;
    const OQSX_EVP_INFO *evp_info =
        pkemctx->kem->oqsx_provider_ctx.oqsx_evp_ctx->evp_info;

    size_t secretLen0 = 0, secretLen1 = 0;
    unsigned char *secret0 = NULL, *secret1 = NULL;

    CompositeCiphertext *cmpCT;
    const unsigned char *p = ct; // temp ptr because d2i_* may move input ct ptr

    ret2 = oqs_qs_kem_decaps_keyslot(vpkemctx, NULL, &secretLen0, NULL, 0, 0);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, 0, err);
    secret0 = OPENSSL_malloc(secretLen0);
    ON_ERR_SET_GOTO(!secret0, ret, 0, err_secret0);

    ret2 = oqs_evp_kem_decaps_keyslot(vpkemctx, NULL, &secretLen1, NULL, 0, 1);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, 0, err_secret0);
    secret1 = OPENSSL_malloc(secretLen1);
    ON_ERR_SET_GOTO(!secret1, ret, 0, err_secret1);

    cmpCT = CompositeCiphertext_new();
    ON_ERR_SET_GOTO(!cmpCT, ret, 0, err_cmpct);

    cmpCT = d2i_CompositeCiphertext(&cmpCT, (const unsigned char **)&p, ctlen);
    ON_ERR_SET_GOTO(!cmpCT, ret, 0, err_cmpct);

    if (secret == NULL) {
        ret2 =
            oqs_kem_combiner(pkemctx, NULL, secretLen1, NULL, secretLen0, NULL,
                             cmpCT->ct2->length, NULL,
                             pkemctx->kem->pubkeylen_cmp[1], NULL, secretlen);
        ON_ERR_SET_GOTO(ret2 != 1, ret, 0, err_cmpct);

        ON_ERR_SET_GOTO(1, ret, 1, err_cmpct);
    }

    ret2 = oqs_qs_kem_decaps_keyslot(vpkemctx, secret0, &secretLen0,
                                     cmpCT->ct1->data, cmpCT->ct1->length, 0);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, 0, err_cmpct);

    ret2 = oqs_evp_kem_decaps_keyslot(vpkemctx, secret1, &secretLen1,
                                      cmpCT->ct2->data, cmpCT->ct2->length, 1);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, 0, err_cmpct);

    ret2 = oqs_kem_combiner(pkemctx, secret1, secretLen1, secret0, secretLen0,
                            cmpCT->ct2->data, cmpCT->ct2->length,
                            pkemctx->kem->comp_pubkey[1],
                            pkemctx->kem->pubkeylen_cmp[1], secret, secretlen);
    ON_ERR_SET_GOTO(!ret2, ret, 0, err_cmpct);

err_cmpct:
    CompositeCiphertext_free(cmpCT);
err_secret1:
    OPENSSL_clear_free(secret1, secretLen1);
err_secret0:
    OPENSSL_clear_free(secret0, secretLen0);
err:
    return ret;
}
