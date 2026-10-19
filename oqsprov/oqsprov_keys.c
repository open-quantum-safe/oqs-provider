// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 key handler.
 *
 * Code strongly inspired by OpenSSL crypto/ec key handler but relocated here
 * to have code within provider.
 *
 */

#include <assert.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

#include "oqs_prov.h"

#ifdef NDEBUG
#define OQS_KEY_PRINTF(a)
#define OQS_KEY_PRINTF2(a, b)
#define OQS_KEY_PRINTF3(a, b, c)
#else
#define OQS_KEY_PRINTF(a)                                                      \
    if (getenv("OQSKEY"))                                                      \
    fprintf(stderr, a)
#define OQS_KEY_PRINTF2(a, b)                                                  \
    if (getenv("OQSKEY"))                                                      \
    fprintf(stderr, a, b)
#define OQS_KEY_PRINTF3(a, b, c)                                               \
    if (getenv("OQSKEY"))                                                      \
    fprintf(stderr, a, b, c)
#endif // NDEBUG

typedef enum { KEY_OP_PUBLIC, KEY_OP_PRIVATE, KEY_OP_KEYGEN } oqsx_key_op_t;

/// NID/name table

typedef struct {
    int nid;
    char *tlsname;
    char *oqsname;
    int keytype;
    int secbits;
} oqs_nid_name_t;

///// OQS_TEMPLATE_FRAGMENT_OQSNAMES_START

#ifdef OQS_KEM_ENCODERS
#define NID_TABLE_LEN 61
#else
#define NID_TABLE_LEN 40
#endif

static oqs_nid_name_t nid_names[NID_TABLE_LEN] = {
#ifdef OQS_KEM_ENCODERS

    {0, "efrodo640aes", OQS_KEM_alg_efrodokem_640_aes, KEY_TYPE_KEM, 128},
    {0, "efrodo640shake", OQS_KEM_alg_efrodokem_640_shake, KEY_TYPE_KEM, 128},
    {0, "efrodo976aes", OQS_KEM_alg_efrodokem_976_aes, KEY_TYPE_KEM, 192},
    {0, "efrodo976shake", OQS_KEM_alg_efrodokem_976_shake, KEY_TYPE_KEM, 192},
    {0, "efrodo1344aes", OQS_KEM_alg_efrodokem_1344_aes, KEY_TYPE_KEM, 256},
    {0, "efrodo1344shake", OQS_KEM_alg_efrodokem_1344_shake, KEY_TYPE_KEM, 256},
    {0, "frodo640aes", OQS_KEM_alg_frodokem_640_aes, KEY_TYPE_KEM, 128},
    {0, "frodo640shake", OQS_KEM_alg_frodokem_640_shake, KEY_TYPE_KEM, 128},
    {0, "frodo976aes", OQS_KEM_alg_frodokem_976_aes, KEY_TYPE_KEM, 192},
    {0, "frodo976shake", OQS_KEM_alg_frodokem_976_shake, KEY_TYPE_KEM, 192},
    {0, "frodo1344aes", OQS_KEM_alg_frodokem_1344_aes, KEY_TYPE_KEM, 256},
    {0, "frodo1344shake", OQS_KEM_alg_frodokem_1344_shake, KEY_TYPE_KEM, 256},
    {0, "mlkem512", OQS_KEM_alg_ml_kem_512, KEY_TYPE_KEM, 128},
    {0, "mlkem768", OQS_KEM_alg_ml_kem_768, KEY_TYPE_KEM, 192},
    {0, "mlkem1024", OQS_KEM_alg_ml_kem_1024, KEY_TYPE_KEM, 256},
    {0, "bikel1", OQS_KEM_alg_bike_l1, KEY_TYPE_KEM, 128},
    {0, "bikel3", OQS_KEM_alg_bike_l3, KEY_TYPE_KEM, 192},
    {0, "bikel5", OQS_KEM_alg_bike_l5, KEY_TYPE_KEM, 256},
    {0, "hqc1", OQS_KEM_alg_hqc_1, KEY_TYPE_KEM, 128},
    {0, "hqc3", OQS_KEM_alg_hqc_3, KEY_TYPE_KEM, 192},
    {0, "hqc5", OQS_KEM_alg_hqc_5, KEY_TYPE_KEM, 256},

#endif /* OQS_KEM_ENCODERS */
    {0, "mldsa44", OQS_SIG_alg_ml_dsa_44, KEY_TYPE_SIG, 128},
    {0, "mldsa65", OQS_SIG_alg_ml_dsa_65, KEY_TYPE_SIG, 192},
    {0, "mldsa87", OQS_SIG_alg_ml_dsa_87, KEY_TYPE_SIG, 256},
    {0, "falcon512", OQS_SIG_alg_falcon_512, KEY_TYPE_SIG, 128},
    {0, "falconpadded512", OQS_SIG_alg_falcon_padded_512, KEY_TYPE_SIG, 128},
    {0, "falcon1024", OQS_SIG_alg_falcon_1024, KEY_TYPE_SIG, 256},
    {0, "falconpadded1024", OQS_SIG_alg_falcon_padded_1024, KEY_TYPE_SIG, 256},
    {0, "mayo1", OQS_SIG_alg_mayo_1, KEY_TYPE_SIG, 128},
    {0, "mayo2", OQS_SIG_alg_mayo_2, KEY_TYPE_SIG, 128},
    {0, "mayo3", OQS_SIG_alg_mayo_3, KEY_TYPE_SIG, 192},
    {0, "mayo5", OQS_SIG_alg_mayo_5, KEY_TYPE_SIG, 256},
    {0, "CROSSrsdp128balanced", OQS_SIG_alg_cross_rsdp_128_balanced,
     KEY_TYPE_SIG, 128},
    {0, "OV_Is_pkc", OQS_SIG_alg_uov_ov_Is_pkc, KEY_TYPE_SIG, 128},
    {0, "OV_Ip_pkc", OQS_SIG_alg_uov_ov_Ip_pkc, KEY_TYPE_SIG, 128},
    {0, "OV_Is_pkc_skc", OQS_SIG_alg_uov_ov_Is_pkc_skc, KEY_TYPE_SIG, 128},
    {0, "OV_Ip_pkc_skc", OQS_SIG_alg_uov_ov_Ip_pkc_skc, KEY_TYPE_SIG, 128},
    {0, "snova1k", OQS_SIG_alg_snova_SNOVA_I_K, KEY_TYPE_SIG, 128},
    {0, "snova1b", OQS_SIG_alg_snova_SNOVA_I_B, KEY_TYPE_SIG, 128},
    {0, "snova1s", OQS_SIG_alg_snova_SNOVA_I_S, KEY_TYPE_SIG, 128},
    {0, "snova3k", OQS_SIG_alg_snova_SNOVA_III_K, KEY_TYPE_SIG, 192},
    {0, "snova3b", OQS_SIG_alg_snova_SNOVA_III_B, KEY_TYPE_SIG, 192},
    {0, "snova3s", OQS_SIG_alg_snova_SNOVA_III_S, KEY_TYPE_SIG, 192},
    {0, "snova5k", OQS_SIG_alg_snova_SNOVA_V_K, KEY_TYPE_SIG, 256},
    {0, "snova5b", OQS_SIG_alg_snova_SNOVA_V_B, KEY_TYPE_SIG, 256},
    {0, "snova5s", OQS_SIG_alg_snova_SNOVA_V_S, KEY_TYPE_SIG, 256},
    {0, "slhdsasha2128s", OQS_SIG_alg_slh_dsa_pure_sha2_128s, KEY_TYPE_SIG,
     128},
    {0, "slhdsasha2128f", OQS_SIG_alg_slh_dsa_pure_sha2_128f, KEY_TYPE_SIG,
     128},
    {0, "slhdsasha2192s", OQS_SIG_alg_slh_dsa_pure_sha2_192s, KEY_TYPE_SIG,
     192},
    {0, "slhdsasha2192f", OQS_SIG_alg_slh_dsa_pure_sha2_192f, KEY_TYPE_SIG,
     192},
    {0, "slhdsasha2256s", OQS_SIG_alg_slh_dsa_pure_sha2_256s, KEY_TYPE_SIG,
     256},
    {0, "slhdsasha2256f", OQS_SIG_alg_slh_dsa_pure_sha2_256f, KEY_TYPE_SIG,
     256},
    {0, "slhdsashake128s", OQS_SIG_alg_slh_dsa_pure_shake_128s, KEY_TYPE_SIG,
     128},
    {0, "slhdsashake128f", OQS_SIG_alg_slh_dsa_pure_shake_128f, KEY_TYPE_SIG,
     128},
    {0, "slhdsashake192s", OQS_SIG_alg_slh_dsa_pure_shake_192s, KEY_TYPE_SIG,
     192},
    {0, "slhdsashake192f", OQS_SIG_alg_slh_dsa_pure_shake_192f, KEY_TYPE_SIG,
     192},
    {0, "slhdsashake256s", OQS_SIG_alg_slh_dsa_pure_shake_256s, KEY_TYPE_SIG,
     256},
    {0, "slhdsashake256f", OQS_SIG_alg_slh_dsa_pure_shake_256f, KEY_TYPE_SIG,
     256},
    {0, "mqom3cat1gf16fastct", OQS_SIG_alg_mqom_mqom3_cat1_gf16_fast_ct,
     KEY_TYPE_SIG, 128},
    {0, "mqom3cat3gf16fastct", OQS_SIG_alg_mqom_mqom3_cat3_gf16_fast_ct,
     KEY_TYPE_SIG, 192},
    {0, "mqom3cat5gf16fastct", OQS_SIG_alg_mqom_mqom3_cat5_gf16_fast_ct,
     KEY_TYPE_SIG, 256},
    ///// OQS_TEMPLATE_FRAGMENT_OQSNAMES_END
};

int oqs_set_nid(char *tlsname, int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (!strcmp(nid_names[i].tlsname, tlsname)) {
            nid_names[i].nid = nid;
            return 1;
        }
    }
    return 0;
}

static int get_secbits(int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].secbits;
    }
    return 0;
}

/* [mb-nohybrids] get_reverseshare() removed (hybrid share-order flag) */

static int get_keytype(int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].keytype;
    }
    return 0;
}

char *get_oqsname(int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].oqsname;
    }
    return 0;
}

static int get_oqsalg_idx(int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return i;
    }
    return -1;
}

/* [mb-nohybrids] oqsx_comp_set_idx(), oqsx_comp_set_offsets() and
 * oqsx_key_set_composites() removed: the single PQ key lives directly in
 * key->privkey / key->pubkey (no component arrays to lay out). */

PROV_OQS_CTX *oqsx_newprovctx(OSSL_LIB_CTX *libctx,
                              const OSSL_CORE_HANDLE *handle, BIO_METHOD *bm) {
    PROV_OQS_CTX *ret = OPENSSL_zalloc(sizeof(PROV_OQS_CTX));
    if (ret) {
        ret->libctx = libctx;
        ret->handle = handle;
        ret->corebiometh = bm;
    }
    return ret;
}

void oqsx_freeprovctx(PROV_OQS_CTX *ctx) {
    OSSL_LIB_CTX_free(ctx->libctx);
    BIO_meth_free(ctx->corebiometh);
    OPENSSL_free(ctx);
}

void oqsx_key_set0_libctx(OQSX_KEY *key, OSSL_LIB_CTX *libctx) {
    key->libctx = libctx;
}

/* convenience function creating OQSX keys from nids (only for sigs) */
static OQSX_KEY *oqsx_key_new_from_nid(OSSL_LIB_CTX *libctx, const char *propq,
                                       int nid) {
    OQS_KEY_PRINTF2("Generating OQSX key for nid %d\n", nid);

    char *tls_algname = (char *)OBJ_nid2sn(nid);
    OQS_KEY_PRINTF2("                    for tls_name %s\n", tls_algname);

    if (!tls_algname) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_WRONG_PARAMETERS);
        return NULL;
    }

    return oqsx_key_new(libctx, get_oqsname(nid), tls_algname, get_keytype(nid),
                        propq, get_secbits(nid), get_oqsalg_idx(nid));
}

/* [mb-nohybrids] setECParams() removed: hybrid-only EC parameter workaround */

/* Key codes */

/* [mb-nohybrids] nids_sig[] (classical halves of composite sigs) removed */
/* [mb-nohybrids] removed hybrid-only classical-curve tables
 * (nids_ecp/ecbp/ecx and OQSX_ECP/ECBP/ECX_NAMES) and the hybrid-only
 * EVP-context initializers (oqsx_hybsig_init(), oqshybkem_init_ecp/ecbp/ecx()).
 * These existed solely to set up the classical (EC/ECX/RSA/EdDSA) half of a
 * hybrid key. A liboqs-primitives-only provider needs none of them. */

/* Re-create OQSX_KEY from encoding(s): Same end-state as after ken-gen */
static OQSX_KEY *oqsx_key_op(const X509_ALGOR *palg, const unsigned char *p,
                             int plen, oqsx_key_op_t op, OSSL_LIB_CTX *libctx,
                             const char *propq) {
    OQSX_KEY *key = NULL;
    void **privkey, **pubkey;
    int nid = NID_undef;
    int ret = 0;

    OQS_KEY_PRINTF2("OQSX KEY: key_op called with data of len %d\n", plen);
    if (palg != NULL) {
        int ptype;

        /* Algorithm parameters must be absent */
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF || !palg || !palg->algorithm) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return 0;
        }
        nid = OBJ_obj2nid(palg->algorithm);
    }

    if (p == NULL || nid == EVP_PKEY_NONE || nid == NID_undef) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
        return 0;
    }

    key = oqsx_key_new_from_nid(libctx, propq, nid);
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    OQS_KEY_PRINTF2("OQSX KEY: Recreated OQSX key %s\n", key->tls_name);

    if (op == KEY_OP_PUBLIC) {
        /* [mb-nohybrids] single-key: no classical length prefix */
        if (key->pubkeylen != plen) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            goto err_key_op;
        }
        if (oqsx_key_allocate_keymaterial(key, 0)) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            goto err_key_op;
        }
        memcpy(key->pubkey, p, plen);
    } else {
        // for plain OQS keys, we expect OQS priv||OQS pub key
        size_t actualprivkeylen = key->privkeylen;
        /* [mb-nohybrids] single-key: no classical private-key prefix */
#ifdef NOPUBKEY_IN_PRIVKEY
        if (actualprivkeylen != plen) {
            OQS_KEY_PRINTF3("OQSX KEY: private key with "
                            "unexpected length %d vs %d\n",
                            plen, (int)(actualprivkeylen));
#else
        if (actualprivkeylen + oqsx_key_get_oqs_public_key_len(key) != plen) {
            OQS_KEY_PRINTF3(
                "OQSX KEY: private key with unexpected length "
                "%d vs %d\n",
                plen,
                (int)(actualprivkeylen + oqsx_key_get_oqs_public_key_len(key)));
#endif
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            goto err_key_op;
        }
        if (oqsx_key_allocate_keymaterial(key, 1)
#ifndef NOPUBKEY_IN_PRIVKEY
            || oqsx_key_allocate_keymaterial(key, 0)
#endif
        ) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            goto err_key_op;
        }
        // first populate private key data
        memcpy(key->privkey, p, actualprivkeylen);
#ifndef NOPUBKEY_IN_PRIVKEY
        // only enough data to fill public OQS key component
        if (oqsx_key_get_oqs_public_key_len(key) != plen - actualprivkeylen) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            goto err_key_op;
        }
        // populate OQS public key structure
        /* [mb-nohybrids] single-key */
        memcpy(key->pubkey, p + key->privkeylen, plen - key->privkeylen);
#endif
    }

    return key;

err_key_op:
    oqsx_key_free(key);
    return NULL;
}

/* [mb-nohybrids] oqsx_key_recreate_classickey() removed: it only rebuilt the
 * classical EVP_PKEY half of a hybrid key. */

OQSX_KEY *oqsx_key_from_x509pubkey(const X509_PUBKEY *xpk, OSSL_LIB_CTX *libctx,
                                   const char *propq) {
    const unsigned char *p;
    int plen;
    X509_ALGOR *palg;
    OQSX_KEY *oqsx = NULL;
    STACK_OF(ASN1_TYPE) *sk = NULL;
    ASN1_TYPE *aType = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    const unsigned char *buf;
    unsigned char *concat_key;
    int count, aux, i, buflen;

    if (!xpk || (!X509_PUBKEY_get0_param(NULL, &p, &plen, &palg, xpk))) {
        return NULL;
    }
    oqsx = oqsx_key_op(palg, p, plen, KEY_OP_PUBLIC, libctx, propq);
    return oqsx;
}

OQSX_KEY *oqsx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                              OSSL_LIB_CTX *libctx, const char *propq) {
    OQSX_KEY *oqsx = NULL;
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;
    STACK_OF(ASN1_TYPE) *sk = NULL;
    ASN1_TYPE *aType = NULL;
    unsigned char *concat_key;
    const unsigned char *buf;
    int count, aux, i, buflen, key_diff = 0;

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8inf))
        return 0;

    oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
    if (oct == NULL) {
        p = NULL;
        plen = 0;
    } else {
        p = ASN1_STRING_get0_data(oct);
        plen = ASN1_STRING_length(oct);
    }

    oqsx = oqsx_key_op(palg, p, plen + key_diff, KEY_OP_PRIVATE, libctx, propq);
    ASN1_OCTET_STRING_free(oct);
    return oqsx;
}

extern const char *oqs_oid_alg_list[];

OQSX_KEY *oqsx_key_new(OSSL_LIB_CTX *libctx, char *oqs_name, char *tls_name,
                       int primitive, const char *propq, int bit_security,
                       int alg_idx) {
    OQSX_KEY *ret = OPENSSL_zalloc(sizeof(*ret));
    int ret2 = 0;

    if (ret == NULL)
        goto err;

#ifdef OQS_PROVIDER_NOATOMIC
    ret->lock = CRYPTO_THREAD_lock_new();
    ON_ERR_GOTO(!ret->lock, err);
#endif

    if (oqs_name == NULL) {
        OQS_KEY_PRINTF("OQSX_KEY: Fatal error: No OQS key name provided:\n");
        goto err;
    }

    if (tls_name == NULL) {
        OQS_KEY_PRINTF("OQSX_KEY: Fatal error: No TLS key name provided:\n");
        goto err;
    }

    switch (primitive) {
    case KEY_TYPE_SIG:
        ret->oqsx_provider_ctx.oqsx_qs_ctx.sig = OQS_SIG_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.sig) {
            fprintf(stderr,
                    "Could not create OQS signature algorithm %s. "
                    "Enabled in "
                    "liboqs?\n",
                    oqs_name);
            goto err;
        }

        ret->privkeylen =
            ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_secret_key;
        ret->pubkeylen =
            ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key;
        ret->keytype = KEY_TYPE_SIG;
        break;
    case KEY_TYPE_KEM:
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = OQS_KEM_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.kem) {
            fprintf(stderr,
                    "Could not create OQS KEM algorithm %s. Enabled "
                    "in liboqs?\n",
                    oqs_name);
            goto err;
        }
        ret->privkeylen =
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key;
        ret->pubkeylen =
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
        ret->keytype = KEY_TYPE_KEM;
        break;
    /* [mb-nohybrids] KEY_TYPE_*_HYB_KEM and KEY_TYPE_HYB_SIG cases removed:
     * these allocated a second (classical) component and set numkeys = 2. */
    default:
        OQS_KEY_PRINTF2("OQSX_KEY: Unknown key type encountered: %d\n",
                        primitive);
        goto err;
    }

    ret->libctx = libctx;
    ret->references = 1;
    ret->tls_name = OPENSSL_strdup(tls_name);
    ON_ERR_GOTO(!ret->tls_name, err);
    ret->bit_security = bit_security;

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        ON_ERR_GOTO(!ret->propq, err);
    }

    OQS_KEY_PRINTF2("OQSX_KEY: new key created: %s\n", ret->tls_name);
    OQS_KEY_PRINTF3("OQSX_KEY: new key created: %p (type: %d)\n", ret,
                    ret->keytype);
    return ret;
err:
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);

    if (!ret)
        return NULL;

#ifdef OQS_PROVIDER_NOATOMIC
    if (ret->lock)
        CRYPTO_THREAD_lock_free(ret->lock);
#endif

    if (ret) {
        OPENSSL_free(ret->tls_name);
        OPENSSL_free(ret->propq);
        OQS_KEM_free(ret->oqsx_provider_ctx.oqsx_qs_ctx.kem);
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = NULL;
        OQS_SIG_free(ret->oqsx_provider_ctx.oqsx_qs_ctx.sig);
        ret->oqsx_provider_ctx.oqsx_qs_ctx.sig = NULL;
    }
    OPENSSL_free(ret);
    return NULL;
}

void oqsx_key_free(OQSX_KEY *key) {
    int refcnt;
    if (key == NULL)
        return;

#ifndef OQS_PROVIDER_NOATOMIC
    refcnt =
        atomic_fetch_sub_explicit(&key->references, 1, memory_order_relaxed) -
        1;
    if (refcnt == 0)
        atomic_thread_fence(memory_order_acquire);
#else
    CRYPTO_atomic_add(&key->references, -1, &refcnt, key->lock);
#endif

    OQS_KEY_PRINTF3("%p:%4d:OQSX_KEY\n", (void *)key, refcnt);
    if (refcnt > 0)
        return;
#ifndef NDEBUG
    assert(refcnt == 0);
#endif

    OPENSSL_free(key->propq);
    OPENSSL_free(key->tls_name);
    OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
    OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
    if (key->keytype == KEY_TYPE_KEM)
        OQS_KEM_free(key->oqsx_provider_ctx.oqsx_qs_ctx.kem);
    else
        OQS_SIG_free(key->oqsx_provider_ctx.oqsx_qs_ctx.sig);

#ifdef OQS_PROVIDER_NOATOMIC
    CRYPTO_THREAD_lock_free(key->lock);
#endif
    OPENSSL_free(key);
}

int oqsx_key_up_ref(OQSX_KEY *key) {
    int refcnt;

#ifndef OQS_PROVIDER_NOATOMIC
    refcnt =
        atomic_fetch_add_explicit(&key->references, 1, memory_order_relaxed) +
        1;
#else
    CRYPTO_atomic_add(&key->references, 1, &refcnt, key->lock);
#endif

    OQS_KEY_PRINTF3("%p:%4d:OQSX_KEY\n", (void *)key, refcnt);
#ifndef NDEBUG
    assert(refcnt > 1);
#endif
    return (refcnt > 1);
}

int oqsx_key_allocate_keymaterial(OQSX_KEY *key, int include_private) {
    int ret = 0, aux = 0;

    aux = SIZE_OF_UINT32;

    if (!key->privkey && include_private) {
        key->privkey = OPENSSL_secure_zalloc(key->privkeylen + aux);
        ON_ERR_SET_GOTO(!key->privkey, ret, 1, err_alloc);
    }
    if (!key->pubkey && !include_private) {
        key->pubkey = OPENSSL_secure_zalloc(key->pubkeylen);
        ON_ERR_SET_GOTO(!key->pubkey, ret, 1, err_alloc);
    }
err_alloc:
    return ret;
}

int oqsx_key_fromdata(OQSX_KEY *key, const OSSL_PARAM params[],
                      int include_private) {
    const OSSL_PARAM *pp1, *pp2;

    OQS_KEY_PRINTF("OQSX Key from data called\n");
    pp1 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    pp2 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    // at least one parameter must be given
    if (pp1 == NULL && pp2 == NULL) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_WRONG_PARAMETERS);
        return 0;
    }
    if (pp1 != NULL && include_private) {
        if (pp1->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return 0;
        }
        if (key->privkeylen != pp1->data_size) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->privkey, pp1->data_size);
        key->privkey = OPENSSL_secure_malloc(pp1->data_size);
        if (key->privkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->privkey, pp1->data, pp1->data_size);
    }
    if (pp2 != NULL) {
        if (pp2->data_type != OSSL_PARAM_OCTET_STRING) {
            OQS_KEY_PRINTF("invalid data type\n");
            return 0;
        }
        if (key->pubkeylen != pp2->data_size) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->pubkey, pp2->data_size);
        key->pubkey = OPENSSL_secure_malloc(pp2->data_size);
        if (key->pubkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->pubkey, pp2->data, pp2->data_size);
    }
    return 1;
}

static int oqsx_key_gen_oqs(OQSX_KEY *key, int gen_kem) {
    if (gen_kem)
        return OQS_KEM_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.kem,
                               key->pubkey, key->privkey);
    else {
        return OQS_SIG_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.sig,
                               key->pubkey, key->privkey);
    }
}

/* [mb-nohybrids] oqsx_key_gen_evp_key_sig() and oqsx_key_gen_evp_key_kem()
 * removed: classical EVP keypair generation for the hybrid components. */

/* Allocate key buffers and component pointers for a plain KEM key without
   generating a key pair; returns 0 on success. */
int oqsx_key_prepare_empty(OQSX_KEY *key) {
    if ((key->privkey == NULL || key->pubkey == NULL) &&
        (oqsx_key_allocate_keymaterial(key, 0) ||
         oqsx_key_allocate_keymaterial(key, 1)))
        return 1;
    return 0;
}

/* allocates OQS and classical keys */
int oqsx_key_gen(OQSX_KEY *key) {
    int ret = 0;

    if (key->privkey == NULL || key->pubkey == NULL) {
        ret = oqsx_key_allocate_keymaterial(key, 0) ||
              oqsx_key_allocate_keymaterial(key, 1);
        ON_ERR_GOTO(ret, err_gen);
    }

    /* [mb-nohybrids] single-key keygen: no classical EVP keypair to generate */
    if (key->keytype == KEY_TYPE_KEM) {
        ret = oqsx_key_gen_oqs(key, 1);
    } else if (key->keytype == KEY_TYPE_SIG) {
        ret = oqsx_key_gen_oqs(key, 0);
    } else {
        ret = 1;
    }
err_gen:
    if (ret) {
        oqsx_key_free(key);
    }
    return ret;
}

int oqsx_key_secbits(OQSX_KEY *key) { return key->bit_security; }

int oqsx_key_maxsize(OQSX_KEY *key) {
    switch (key->keytype) {
    case KEY_TYPE_KEM:
        return key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_SIG:
        return key->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature;
    default:
        OQS_KEY_PRINTF("OQSX KEY: Wrong key type\n");
        return 0;
    }
}

int oqsx_key_get_oqs_public_key_len(OQSX_KEY *k) {
    switch (k->keytype) {
    case KEY_TYPE_SIG:
    case KEY_TYPE_KEM:
        return k->pubkeylen;
    default:
        OQS_KEY_PRINTF2("OQSX_KEY: Unknown key type encountered: %d\n",
                        k->keytype);
        return -1;
    }
}
