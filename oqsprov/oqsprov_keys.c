// SPDX-License-Identifier: Apache-2.0 AND MIT

/* 
 * OQS OpenSSL 3 key handler.
 * 
 * Code strongly inspired by OpenSSL crypto/ec key handler but relocated here 
 * to have code within provider.
 *
 */

#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string.h>
#include <assert.h>
#include "oqs_prov.h"

#ifdef NDEBUG
#define OQS_KEY_PRINTF(a)
#define OQS_KEY_PRINTF2(a, b)
#define OQS_KEY_PRINTF3(a, b, c)
#else
#define OQS_KEY_PRINTF(a) if (getenv("OQSKEY")) printf(a)
#define OQS_KEY_PRINTF2(a, b) if (getenv("OQSKEY")) printf(a, b)
#define OQS_KEY_PRINTF3(a, b, c) if (getenv("OQSKEY")) printf(a, b, c)
#endif // NDEBUG

typedef enum {
    KEY_OP_PUBLIC,
    KEY_OP_PRIVATE,
    KEY_OP_KEYGEN
} oqsx_key_op_t;

/// NID/name table

typedef struct {
    int nid;
    char* tlsname;
    char* oqsname;
    int keytype;
    int secbits;
} oqs_nid_name_t;

///// OQS_TEMPLATE_FRAGMENT_OQSNAMES_START
#define NID_TABLE_LEN 36

static oqs_nid_name_t nid_names[NID_TABLE_LEN] = {
       { 0, "dilithium2", OQS_SIG_alg_dilithium_2, KEY_TYPE_SIG, 128 },
       { 0, "p256_dilithium2", OQS_SIG_alg_dilithium_2, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_dilithium2", OQS_SIG_alg_dilithium_2, KEY_TYPE_HYB_SIG, 128 },
       { 0, "dilithium3", OQS_SIG_alg_dilithium_3, KEY_TYPE_SIG, 192 },
       { 0, "p384_dilithium3", OQS_SIG_alg_dilithium_3, KEY_TYPE_HYB_SIG, 192 },
       { 0, "dilithium5", OQS_SIG_alg_dilithium_5, KEY_TYPE_SIG, 256 },
       { 0, "p521_dilithium5", OQS_SIG_alg_dilithium_5, KEY_TYPE_HYB_SIG, 256 },
       { 0, "dilithium2_aes", OQS_SIG_alg_dilithium_2_aes, KEY_TYPE_SIG, 128 },
       { 0, "p256_dilithium2_aes", OQS_SIG_alg_dilithium_2_aes, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_dilithium2_aes", OQS_SIG_alg_dilithium_2_aes, KEY_TYPE_HYB_SIG, 128 },
       { 0, "dilithium3_aes", OQS_SIG_alg_dilithium_3_aes, KEY_TYPE_SIG, 192 },
       { 0, "p384_dilithium3_aes", OQS_SIG_alg_dilithium_3_aes, KEY_TYPE_HYB_SIG, 192 },
       { 0, "dilithium5_aes", OQS_SIG_alg_dilithium_5_aes, KEY_TYPE_SIG, 256 },
       { 0, "p521_dilithium5_aes", OQS_SIG_alg_dilithium_5_aes, KEY_TYPE_HYB_SIG, 256 },
       { 0, "falcon512", OQS_SIG_alg_falcon_512, KEY_TYPE_SIG, 128 },
       { 0, "p256_falcon512", OQS_SIG_alg_falcon_512, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_falcon512", OQS_SIG_alg_falcon_512, KEY_TYPE_HYB_SIG, 128 },
       { 0, "falcon1024", OQS_SIG_alg_falcon_1024, KEY_TYPE_SIG, 256 },
       { 0, "p521_falcon1024", OQS_SIG_alg_falcon_1024, KEY_TYPE_HYB_SIG, 256 },
       { 0, "picnicl1full", OQS_SIG_alg_picnic_L1_full, KEY_TYPE_SIG, 128 },
       { 0, "p256_picnicl1full", OQS_SIG_alg_picnic_L1_full, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_picnicl1full", OQS_SIG_alg_picnic_L1_full, KEY_TYPE_HYB_SIG, 128 },
       { 0, "picnic3l1", OQS_SIG_alg_picnic3_L1, KEY_TYPE_SIG, 128 },
       { 0, "p256_picnic3l1", OQS_SIG_alg_picnic3_L1, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_picnic3l1", OQS_SIG_alg_picnic3_L1, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rainbowVclassic", OQS_SIG_alg_rainbow_V_classic, KEY_TYPE_SIG, 256 },
       { 0, "p521_rainbowVclassic", OQS_SIG_alg_rainbow_V_classic, KEY_TYPE_HYB_SIG, 256 },
       { 0, "sphincsharaka128frobust", OQS_SIG_alg_sphincs_haraka_128f_robust, KEY_TYPE_SIG, 128 },
       { 0, "p256_sphincsharaka128frobust", OQS_SIG_alg_sphincs_haraka_128f_robust, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_sphincsharaka128frobust", OQS_SIG_alg_sphincs_haraka_128f_robust, KEY_TYPE_HYB_SIG, 128 },
       { 0, "sphincssha256128frobust", OQS_SIG_alg_sphincs_sha256_128f_robust, KEY_TYPE_SIG, 128 },
       { 0, "p256_sphincssha256128frobust", OQS_SIG_alg_sphincs_sha256_128f_robust, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_sphincssha256128frobust", OQS_SIG_alg_sphincs_sha256_128f_robust, KEY_TYPE_HYB_SIG, 128 },
       { 0, "sphincsshake256128frobust", OQS_SIG_alg_sphincs_shake256_128f_robust, KEY_TYPE_SIG, 128 },
       { 0, "p256_sphincsshake256128frobust", OQS_SIG_alg_sphincs_shake256_128f_robust, KEY_TYPE_HYB_SIG, 128 },
       { 0, "rsa3072_sphincsshake256128frobust", OQS_SIG_alg_sphincs_shake256_128f_robust, KEY_TYPE_HYB_SIG, 128 },
///// OQS_TEMPLATE_FRAGMENT_OQSNAMES_END
};

int oqs_set_nid(char* tlsname, int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (!strcmp(nid_names[i].tlsname, tlsname)) {
          nid_names[i].nid = nid;
          return 1;
      }
   }
   return 0;
}

static int get_secbits(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].secbits;
   }
   return 0; 
}

static int get_keytype(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].keytype;
   }
   return 0; 
}

static char* get_oqsname(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].oqsname;
   }
   return 0; 
}

static int oqsx_key_set_composites(OQSX_KEY *key) {
	int ret = 0;

	if (key->numkeys == 1) {
		key->comp_privkey[0] = key->privkey;
		key->comp_pubkey[0] = key->pubkey;
	}
	else { // TBD: extend for more than 1 classic key:
		int classic_pubkey_len, classic_privkey_len;

		if (key->privkey) {
			key->comp_privkey[0] = key->privkey + SIZE_OF_UINT32;
			DECODE_UINT32(classic_privkey_len, key->privkey);
			key->comp_privkey[1] = key->privkey + classic_privkey_len + SIZE_OF_UINT32;
		}
		else {
			key->comp_privkey[0] = NULL;
			key->comp_privkey[1] = NULL;
		}
		if (key->pubkey) {
			key->comp_pubkey[0] = key->pubkey + SIZE_OF_UINT32;
			DECODE_UINT32(classic_pubkey_len, key->pubkey);
			key->comp_pubkey[1] = key->pubkey + classic_pubkey_len + SIZE_OF_UINT32;
		}
		else {
			key->comp_pubkey[0] = NULL;
			key->comp_pubkey[1] = NULL;
		}
	}
	err:
	return ret;
}

PROV_OQS_CTX *oqsx_newprovctx(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle, BIO_METHOD *bm) {
    PROV_OQS_CTX * ret = OPENSSL_zalloc(sizeof(PROV_OQS_CTX));
    if (ret) {
       ret->libctx = libctx;
       ret->handle = handle;
       ret->corebiometh = bm;
    }
    return ret;
}

void oqsx_freeprovctx(PROV_OQS_CTX *ctx) {
    OPENSSL_free(ctx);
}


void oqsx_key_set0_libctx(OQSX_KEY *key, OSSL_LIB_CTX *libctx)
{
    key->libctx = libctx;
}

/* convenience function creating OQSX keys from nids (only for sigs) */
static OQSX_KEY *oqsx_key_new_from_nid(OSSL_LIB_CTX *libctx, const char *propq, int nid) {
	OQS_KEY_PRINTF2("Generating OQSX key for nid %d\n", nid);

	char* tls_algname = (char *)OBJ_nid2sn(nid);
	OQS_KEY_PRINTF2("                    for tls_name %s\n", tls_algname);

	if (!tls_algname) {
		ERR_raise(ERR_LIB_USER, OQSPROV_R_WRONG_PARAMETERS);
		return NULL;
	}

	return oqsx_key_new(libctx, get_oqsname(nid), tls_algname, get_keytype(nid), propq, get_secbits(nid));
}

/* Workaround for not functioning EC PARAM initialization
 * TBD, check https://github.com/openssl/openssl/issues/16989
 */
EVP_PKEY* setECParams(EVP_PKEY *eck, int nid) {
    const unsigned char p256params[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    const unsigned char p384params[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
    const unsigned char p521params[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };

    const unsigned char* params;
    switch(nid) {
        case NID_X9_62_prime256v1:
            params = p256params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p256params));
        case NID_secp384r1:
            params = p384params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p384params));
        case NID_secp521r1:
            params = p521params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p521params));
        default:
            return NULL;
    }
}

/* Re-create OQSX_KEY from encoding(s): Same end-state as after ken-gen */
static OQSX_KEY *oqsx_key_op(const X509_ALGOR *palg,
                      const unsigned char *p, int plen,
                      oqsx_key_op_t op,
                      OSSL_LIB_CTX *libctx, const char *propq)
{
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

    if (op == KEY_OP_PUBLIC) {
        if (key->pubkeylen != plen) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            goto err;
        }
        if (oqsx_key_allocate_keymaterial(key, 0)) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(key->pubkey, p, plen);
    } else {
        if (key->privkeylen+key->pubkeylen != plen) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            goto err;
        }
        if (oqsx_key_allocate_keymaterial(key, 1)) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(key->privkey, p, key->privkeylen);
        memcpy(key->pubkey, p+key->privkeylen, key->pubkeylen);
    }
    ret = oqsx_key_set_composites(key);
    ON_ERR_GOTO(ret, err);
    if (key->numkeys == 2) { // hybrid key
        int classical_pubkey_len, classical_privkey_len;
        if (!key->evp_info) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_EVPINFO_MISSING);
            goto err;
        }
	if (op == KEY_OP_PUBLIC) {
            DECODE_UINT32(classical_pubkey_len, key->pubkey);
            if (key->evp_info->raw_key_support) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                goto err;
            }
            else {
                const unsigned char* enc_pubkey = key->comp_pubkey[0];
                EVP_PKEY* npk = EVP_PKEY_new();
                if (key->evp_info->keytype != EVP_PKEY_RSA) {
                    npk = setECParams(npk, key->evp_info->nid);
                }
                key->classical_pkey = d2i_PublicKey(key->evp_info->keytype, &npk, &enc_pubkey, classical_pubkey_len);
                if (!key->classical_pkey) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err;
                }
            }
        }
	if (op == KEY_OP_PRIVATE) {
            DECODE_UINT32(classical_privkey_len, key->privkey);
            if (key->evp_info->raw_key_support) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                goto err;
            }
            else {
                const unsigned char* enc_privkey = key->comp_privkey[0];
                key->classical_pkey = d2i_PrivateKey(key->evp_info->keytype, NULL, &enc_privkey, classical_privkey_len);
                if (!key->classical_pkey) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err;
                }
            }
        }
    }

    return key;

 err:
    oqsx_key_free(key);
    return NULL;
}

OQSX_KEY *oqsx_key_from_x509pubkey(const X509_PUBKEY *xpk,
                              OSSL_LIB_CTX *libctx, const char *propq)
{
    const unsigned char *p;
    int plen;
    X509_ALGOR *palg;
    OQSX_KEY* oqsx = NULL;

    if (!xpk || (!X509_PUBKEY_get0_param(NULL, &p, &plen, &palg, xpk))) {
        return NULL;
    }
    oqsx = oqsx_key_op(palg, p, plen, KEY_OP_PUBLIC, libctx, propq);
    return oqsx;
}

OQSX_KEY *oqsx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                              OSSL_LIB_CTX *libctx, const char *propq)
{
    OQSX_KEY *oqsx = NULL;
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;

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

    oqsx = oqsx_key_op(palg, p, plen, KEY_OP_PRIVATE,
                       libctx, propq);
    ASN1_OCTET_STRING_free(oct);
    return oqsx;
}

/* Key codes */

static const OQSX_EVP_INFO nids_sig[] = {
        { EVP_PKEY_EC,  NID_X9_62_prime256v1, 0, 65 , 121,  32,  72}, // 128 bit
        { EVP_PKEY_EC,  NID_secp384r1       , 0, 97 , 167,  48, 104}, // 192 bit
        { EVP_PKEY_EC,  NID_secp521r1       , 0, 133, 223,  66, 141}, // 256 bit
        { EVP_PKEY_RSA, NID_rsaEncryption   , 0, 398, 1770, 0,  384}, // 128 bit
};

static const OQSX_EVP_INFO nids_ecp[] = {
        { EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65 , 121, 32, 0}, // 128 bit
        { EVP_PKEY_EC, NID_secp384r1       , 0, 97 , 167, 48, 0}, // 192 bit
        { EVP_PKEY_EC, NID_secp521r1       , 0, 133, 223, 66, 0}  // 256 bit
};

static const OQSX_EVP_INFO nids_ecx[] = {
        { EVP_PKEY_X25519, 0, 1, 32, 32, 32, 0}, // 128 bit
        { EVP_PKEY_X448,   0, 1, 56, 56, 56, 0}, // 192 bit
        { 0,               0, 0,  0,  0,  0, 0}  // 256 bit
};

static int oqsx_hybsig_init(int bit_security, OQSX_EVP_CTX *evp_ctx, char* algname)
{
    int ret = 1;
    int idx = (bit_security - 128) / 64;
    ON_ERR_GOTO(idx < 0 || idx > 2, err);

    if (!strncmp(algname, "rsa3072_", 8)) idx += 3;
    else if (algname[0]!='p') {
        OQS_KEY_PRINTF2("OQS KEY: Incorrect hybrid name: %s\n", algname);
        ret = 0;
        goto err;
    }

    ON_ERR_GOTO(idx < 0 || idx > 3, err);

    evp_ctx->evp_info = &nids_sig[idx];

    evp_ctx->ctx = EVP_PKEY_CTX_new_id(evp_ctx->evp_info->keytype, NULL);
    ON_ERR_GOTO(!evp_ctx->ctx, err);

    if (idx < 3) { // EC
	ret = EVP_PKEY_paramgen_init(evp_ctx->ctx);
	ON_ERR_GOTO(ret <= 0, err);

        ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx->ctx, evp_ctx->evp_info->nid);
	ON_ERR_GOTO(ret <= 0, err);

	ret = EVP_PKEY_paramgen(evp_ctx->ctx, &evp_ctx->keyParam);
	ON_ERR_GOTO(ret <= 0 || !evp_ctx->keyParam, err);
    }
    // RSA bit length set only during keygen

    err:
    return ret;
}

static const int oqshybkem_init_ecp(int bit_security, OQSX_EVP_CTX *evp_ctx)
{
    int ret = 1;
    int idx = (bit_security - 128) / 64;
    ON_ERR_GOTO(idx < 0 || idx > 2, err);

    evp_ctx->evp_info = &nids_ecp[idx];

    evp_ctx->ctx = EVP_PKEY_CTX_new_id(evp_ctx->evp_info->keytype, NULL);
    ON_ERR_GOTO(!evp_ctx->ctx, err);

    ret = EVP_PKEY_paramgen_init(evp_ctx->ctx);
    ON_ERR_GOTO(ret <= 0, err);

    ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx->ctx, evp_ctx->evp_info->nid);
    ON_ERR_GOTO(ret <= 0, err);

    ret = EVP_PKEY_paramgen(evp_ctx->ctx, &evp_ctx->keyParam);
    ON_ERR_GOTO(ret <= 0 || !evp_ctx->keyParam, err);

    err:
    return ret;
}

static const int oqshybkem_init_ecx(int bit_security, OQSX_EVP_CTX *evp_ctx)
{
    int ret = 1;
    int idx = (bit_security - 128) / 64;
    ON_ERR_GOTO(idx < 0 || idx > 2, err);

    evp_ctx->evp_info = &nids_ecx[idx];

    evp_ctx->keyParam = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!evp_ctx->keyParam, ret, -1, err);

    ret = EVP_PKEY_set_type(evp_ctx->keyParam, evp_ctx->evp_info->keytype);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    evp_ctx->ctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
    ON_ERR_SET_GOTO(!evp_ctx->ctx, ret, -1, err);

    err:
    return ret;
}

static const int (*init_kex_fun[])(int, OQSX_EVP_CTX *) = {
        oqshybkem_init_ecp,
        oqshybkem_init_ecx
};

OQSX_KEY *oqsx_key_new(OSSL_LIB_CTX *libctx, char* oqs_name, char* tls_name, int primitive, const char *propq, int bit_security)
{
    OQSX_KEY *ret = OPENSSL_zalloc(sizeof(*ret));
    OQSX_EVP_CTX *evp_ctx = NULL;
    int ret2 = 0;

    if (ret == NULL) goto err;

    if (oqs_name == NULL) {
        OQS_KEY_PRINTF("OQSX_KEY: Fatal error: No OQS key name provided:\n");
        goto err;
    }

    if (tls_name == NULL) {
        OQS_KEY_PRINTF("OQSX_KEY: Fatal error: No TLS key name provided:\n");
        goto err;
    }

    switch(primitive) {
    case KEY_TYPE_SIG:
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ret->oqsx_provider_ctx.oqsx_qs_ctx.sig = OQS_SIG_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.sig) {
            fprintf(stderr, "Could not create OQS signature algorithm %s. Enabled in liboqs?\n", oqs_name);
            goto err;
        }
        ret->privkeylen = ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_secret_key;
        ret->pubkeylen = ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key;
        ret->keytype = KEY_TYPE_SIG;
	break;
    case KEY_TYPE_KEM:
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = OQS_KEM_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.kem) {
            fprintf(stderr, "Could not create OQS KEM algorithm %s. Enabled in liboqs?\n", oqs_name);
            goto err;
        }
        ret->privkeylen = ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key;
        ret->pubkeylen = ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
        ret->keytype = KEY_TYPE_KEM;
	break;
    case KEY_TYPE_ECX_HYB_KEM:
    case KEY_TYPE_ECP_HYB_KEM:
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = OQS_KEM_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.kem) {
            fprintf(stderr, "Could not create OQS KEM algorithm %s. Enabled in liboqs?\n", oqs_name);
            goto err;
        }
        evp_ctx = OPENSSL_zalloc(sizeof(OQSX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

        ret2 = (init_kex_fun[primitive - KEY_TYPE_ECP_HYB_KEM])
                (bit_security, evp_ctx);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->keyParam || !evp_ctx->ctx, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->privkeylen = (ret->numkeys-1)*SIZE_OF_UINT32 + ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key + evp_ctx->evp_info->length_private_key;
        ret->pubkeylen = (ret->numkeys-1)*SIZE_OF_UINT32 + ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key + evp_ctx->evp_info->length_public_key;
        ret->oqsx_provider_ctx.oqsx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
	break;
    case KEY_TYPE_HYB_SIG:
        ret->oqsx_provider_ctx.oqsx_qs_ctx.sig = OQS_SIG_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.sig) {
            fprintf(stderr, "Could not create OQS signature algorithm %s. Enabled in liboqs?\n", oqs_name);
            goto err;
        }
        evp_ctx = OPENSSL_zalloc(sizeof(OQSX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

	ret2 = oqsx_hybsig_init(bit_security, evp_ctx, tls_name);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->ctx, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->privkeylen = (ret->numkeys-1) * SIZE_OF_UINT32 + ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_secret_key + evp_ctx->evp_info->length_private_key;
        ret->pubkeylen = (ret->numkeys-1) * SIZE_OF_UINT32 + ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key + evp_ctx->evp_info->length_public_key;
        ret->oqsx_provider_ctx.oqsx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
	ret->evp_info = evp_ctx->evp_info;
	break;
    default: 
        OQS_KEY_PRINTF2("OQSX_KEY: Unknown key type encountered: %d\n", primitive);
	goto err;
    }

    ret->libctx = libctx;
    ret->references = 1;
    ret->tls_name = OPENSSL_strdup(tls_name);
    ret->bit_security = bit_security;

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        if (ret->propq == NULL)
            goto err;
    }

    OQS_KEY_PRINTF2("OQSX_KEY: new key created: %p\n", ret);
    return ret;
err:
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(ret);
    return NULL;
}

void oqsx_key_free(OQSX_KEY *key)
{
    int refcnt;

    if (key == NULL)
        return;

    refcnt = atomic_fetch_sub_explicit(&key->references, 1,
                                       memory_order_relaxed) - 1;
    if (refcnt == 0)
        atomic_thread_fence(memory_order_acquire);
    OQS_KEY_PRINTF3("%p:%4d:OQSX_KEY\n", (void*)key, refcnt);
    if (refcnt > 0)
        return;
#ifndef NDEBUG
    assert(refcnt == 0);
#endif

    OPENSSL_free(key->propq);
    OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
    OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
    OPENSSL_free(key->comp_pubkey);
    OPENSSL_free(key->comp_privkey);
    if (key->keytype == KEY_TYPE_KEM)
        OQS_KEM_free(key->oqsx_provider_ctx.oqsx_qs_ctx.kem);
    else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM) {
        OQS_KEM_free(key->oqsx_provider_ctx.oqsx_qs_ctx.kem);
        EVP_PKEY_CTX_free(key->oqsx_provider_ctx.oqsx_evp_ctx->ctx);
        EVP_PKEY_free(key->oqsx_provider_ctx.oqsx_evp_ctx->keyParam);
        OPENSSL_free(key->oqsx_provider_ctx.oqsx_evp_ctx);
    } else
        OQS_SIG_free(key->oqsx_provider_ctx.oqsx_qs_ctx.sig);
    OPENSSL_free(key->classical_pkey);
    OPENSSL_free(key);
}

int oqsx_key_up_ref(OQSX_KEY *key)
{
    int refcnt;

    refcnt = atomic_fetch_add_explicit(&key->references, 1,
                                       memory_order_relaxed) + 1;
    OQS_KEY_PRINTF3("%p:%4d:OQSX_KEY\n", (void*)key, refcnt);
#ifndef NDEBUG
    assert(refcnt > 1);
#endif
    return (refcnt > 1);
}

int oqsx_key_allocate_keymaterial(OQSX_KEY *key, int include_private)
{
    int ret = 0;

    if (!key->privkey && include_private) {
        key->privkey = OPENSSL_secure_zalloc(key->privkeylen);
        ON_ERR_SET_GOTO(!key->privkey, ret, 1, err);
    }
    if (!key->pubkey) {
        key->pubkey = OPENSSL_secure_zalloc(key->pubkeylen);
        ON_ERR_SET_GOTO(!key->pubkey, ret, 1, err);
    }
    err:
    return ret;
}

int oqsx_key_fromdata(OQSX_KEY *key, const OSSL_PARAM params[], int include_private)
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return 0;
        }
        if (key->privkeylen != p->data_size) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->privkey, p->data_size);
        key->privkey = OPENSSL_secure_malloc(p->data_size);
        if (key->privkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->privkey, p->data, p->data_size);
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            OQS_KEY_PRINTF("invalid data type\n");
            return 0;
        }
        if (key->pubkeylen != p->data_size) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
            return 0;
        }
        OPENSSL_secure_clear_free(key->pubkey, p->data_size);
        key->pubkey = OPENSSL_secure_malloc(p->data_size);
        if (key->pubkey == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(key->pubkey, p->data, p->data_size);
    }
    return 1;
}

// OQS key always the last of the numkeys comp keys
static int oqsx_key_gen_oqs(OQSX_KEY *key, int gen_kem) {
	if (gen_kem)
		return OQS_KEM_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.kem, key->comp_pubkey[key->numkeys-1], key->comp_privkey[key->numkeys-1]);
	else
		return OQS_SIG_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.sig, key->comp_pubkey[key->numkeys-1], key->comp_privkey[key->numkeys-1]);
}

/* Generate classic keys, store length in leading SIZE_OF_UINT32 bytes of pubkey/privkey buffers;
 * returned EVP_PKEY must be freed if not used
 */
static EVP_PKEY* oqsx_key_gen_evp_key(OQSX_EVP_CTX *ctx, unsigned char *pubkey, unsigned char *privkey)
{
    int ret = 0, ret2 = 0;

    // Free at errhyb:
    EVP_PKEY_CTX *kgctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkey_encoded = NULL;

    size_t pubkeylen = 0, privkeylen = 0;

    if (ctx->keyParam)
       kgctx = EVP_PKEY_CTX_new(ctx->keyParam, NULL);
    else
       kgctx = EVP_PKEY_CTX_new_id( ctx->evp_info->nid, NULL );
    ON_ERR_SET_GOTO(!kgctx, ret, -1, errhyb);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    if (ctx->evp_info->keytype == EVP_PKEY_RSA) {
	ret2 = EVP_PKEY_CTX_set_rsa_keygen_bits(kgctx, 3072);
	ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    }
    ret2 = EVP_PKEY_keygen(kgctx, &pkey);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -2, errhyb);

    if (ctx->evp_info->raw_key_support) {
        // TODO: If available, use preallocated memory
        pubkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey_encoded);
        ON_ERR_SET_GOTO(pubkeylen != ctx->evp_info->length_public_key || !pubkey_encoded, ret, -3, errhyb);
        memcpy(pubkey+SIZE_OF_UINT32, pubkey_encoded, pubkeylen);
        privkeylen = ctx->evp_info->length_private_key;
        ret2 = EVP_PKEY_get_raw_private_key(pkey, privkey+SIZE_OF_UINT32, &privkeylen);
        ON_ERR_SET_GOTO(ret2 <= 0 || privkeylen != ctx->evp_info->length_private_key, ret, -4, errhyb);
    }
    else {
        unsigned char* pubkey_enc = pubkey+SIZE_OF_UINT32;
        const unsigned char* pubkey_enc2 = pubkey+SIZE_OF_UINT32;
        pubkeylen = i2d_PublicKey(pkey, &pubkey_enc);
        ON_ERR_SET_GOTO(!pubkey_enc || pubkeylen > (int) ctx->evp_info->length_public_key, ret, -11, errhyb);
        unsigned char* privkey_enc = privkey+SIZE_OF_UINT32;
        const unsigned char* privkey_enc2 = privkey+SIZE_OF_UINT32;
        privkeylen = i2d_PrivateKey(pkey, &privkey_enc);
        ON_ERR_SET_GOTO(!privkey_enc || privkeylen > (int) ctx->evp_info->length_private_key, ret, -12, errhyb);
        // selftest:
        EVP_PKEY* ck2 = d2i_PrivateKey(ctx->evp_info->keytype, NULL, &privkey_enc2, privkeylen);
        ON_ERR_SET_GOTO(!ck2, ret, -14, errhyb);
    }
    ENCODE_UINT32(pubkey,pubkeylen);
    ENCODE_UINT32(privkey,privkeylen);
    OQS_KEY_PRINTF3("OQSKM: Storing classical privkeylen: %ld & pubkeylen: %ld\n", privkeylen, pubkeylen);

    EVP_PKEY_CTX_free(kgctx);
    OPENSSL_free(pubkey_encoded);
    return pkey;

    errhyb:
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_encoded);
    return NULL;
}

/* allocates OQS and classical keys; retains EVP_PKEY on success for sig OQSX_KEY */
int oqsx_key_gen(OQSX_KEY *key)
{
    int ret = 0;
    EVP_PKEY* pkey = NULL;

    if (key->privkey == NULL || key->pubkey == NULL) {
        ret = oqsx_key_allocate_keymaterial(key, 1);
        ON_ERR_GOTO(ret, err);
    }

    if (key->keytype == KEY_TYPE_KEM) {
	ret = oqsx_key_set_composites(key);
        ON_ERR_GOTO(ret, err);
        ret = oqsx_key_gen_oqs(key, 1);
    } else if (key->keytype == KEY_TYPE_ECP_HYB_KEM || key->keytype == KEY_TYPE_ECX_HYB_KEM || key->keytype == KEY_TYPE_HYB_SIG) {
        pkey = oqsx_key_gen_evp_key(key->oqsx_provider_ctx.oqsx_evp_ctx, key->pubkey, key->privkey);
        ON_ERR_GOTO(pkey==NULL, err);
        ret = oqsx_key_set_composites(key);
        ON_ERR_GOTO(ret, err);
        OQS_KEY_PRINTF3("OQSKM: OQSX_KEY privkeylen %ld & pubkeylen: %ld\n", key->privkeylen, key->pubkeylen);

        if (key->keytype == KEY_TYPE_HYB_SIG) {
           key->classical_pkey = pkey;
           ret = oqsx_key_gen_oqs(key, 0);
	}
	else {
           EVP_PKEY_free(pkey);
           ret = oqsx_key_gen_oqs(key, 1);
	}
    } else if (key->keytype == KEY_TYPE_SIG) {
        ret = oqsx_key_set_composites(key);
        ON_ERR_GOTO(ret, err);
        ret = oqsx_key_gen_oqs(key, 0);
    } else {
        ret = 1;
    }
    err:
	if (ret) {
		EVP_PKEY_free(pkey);
		key->classical_pkey = NULL;
	}
    return ret;
}

int oqsx_key_secbits(OQSX_KEY *key) {
    return key->bit_security;
}

int oqsx_key_maxsize(OQSX_KEY *key) {
    switch(key->keytype) {
    case KEY_TYPE_KEM:
	return key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_ECP_HYB_KEM:
    case KEY_TYPE_ECX_HYB_KEM:
	return key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->kex_length_secret + key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_SIG:
	return key->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature;
    case KEY_TYPE_HYB_SIG:
	return key->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature + key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->length_signature+SIZE_OF_UINT32;
    default:
	OQS_KEY_PRINTF("OQSX KEY: Wrong key type\n");
	return 0;
    }
}
