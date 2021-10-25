// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 key handler.
 *
 * Code strongly inspired by OpenSSL crypto/ecx key handler but relocated here to have code within provider.
 *
 * ToDo: Review whether more functions are needed for sig, hybrids.
 */

/* Internal OQS functions for other submodules: not for application use */

#ifndef OQSX_H
# define OQSX_H

# include <stdatomic.h>
# include <openssl/opensslconf.h>
# include <openssl/bio.h>

#  include <openssl/core.h>
#  include <openssl/e_os2.h>

// internal, but useful OSSL define:
# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))

// our own error codes:
#define OQSPROV_R_INVALID_DIGEST                            1
#define OQSPROV_R_INVALID_SIZE                              2
#define OQSPROV_R_INVALID_KEY                               3
#define OQSPROV_R_UNSUPPORTED                               4
#define OQSPROV_R_MISSING_OID                               5 
#define OQSPROV_R_OBJ_CREATE_ERR                            6
#define OQSPROV_R_INVALID_ENCODING                          7
#define OQSPROV_R_SIGN_ERROR				    8
#define OQSPROV_R_LIB_CREATE_ERR			    9

/* Extras for OQS extension */

#define ON_ERR_SET_GOTO(condition, ret, code, gt) \
    if ((condition)) {                            \
        printf("ON_ERR_CONDITION: %d, setting code: %d\n", condition, code); fflush(stdout);   \
        (ret) = (code);                           \
        goto gt;                                  \
    }

#define ON_ERR_GOTO(condition, gt) \
    if ((condition)) {                        \
        printf("ON_ERR_CONDITION: %d\n", condition); fflush(stdout);   \
        goto gt;                              \
    }

#define ECP_NAME(secbits, oqsname) \
    (secbits == 128 ? "p256_" #oqsname "" : \
     secbits == 192 ? "p384_" #oqsname "" : \
                      "p521_" #oqsname "")
#define ECX_NAME(secbits, oqsname) \
    (secbits == 128 ? "x25519_" #oqsname "" : \
                        "x448_" #oqsname "")

typedef struct prov_oqs_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;         /* For all provider modules */
    BIO_METHOD *corebiometh; 
} PROV_OQS_CTX;

PROV_OQS_CTX *oqsx_newprovctx(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle, BIO_METHOD *bm);
void oqsx_freeprovctx(PROV_OQS_CTX *ctx);
# define PROV_OQS_LIBCTX_OF(provctx) (((PROV_OQS_CTX *)provctx)->libctx)

#include "oqs/oqs.h"

struct oqsx_kex_info_st {
    int nid_kex;
    int nid_kex_crv;
    int raw_key_support;
    size_t kex_length_public_key;
    size_t kex_length_private_key;
    size_t kex_length_secret;
};

typedef struct oqsx_kex_info_st OQSX_KEX_INFO;

struct oqsx_evp_ctx_st {
    EVP_PKEY_CTX *kex;
    EVP_PKEY *kexParam;
    const OQSX_KEX_INFO *kex_info;
};

typedef struct oqsx_evp_ctx_st OQSX_EVP_CTX;

typedef union {
    OQS_SIG *sig;
    OQS_KEM *kem;
} OQSX_QS_CTX;

struct oqsx_provider_ctx_st {
    OQSX_QS_CTX oqsx_qs_ctx;
    OQSX_EVP_CTX *oqsx_evp_ctx;
};

typedef struct oqsx_provider_ctx_st OQSX_PROVIDER_CTX;

enum oqsx_key_type_en {
    KEY_TYPE_SIG, KEY_TYPE_KEM, KEY_TYPE_ECP_HYB_KEM, KEY_TYPE_ECX_HYB_KEM
};

typedef enum oqsx_key_type_en OQSX_KEY_TYPE;

struct oqsx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    OQSX_KEY_TYPE keytype;
    OQSX_PROVIDER_CTX oqsx_provider_ctx;
    size_t numkeys;
    size_t privkeylen;
    size_t pubkeylen;
    size_t bit_security;
    char *oqs_name;
    char *tls_name;
    _Atomic int references;
    void **comp_privkey;
    void **comp_pubkey;
    void *privkey;
    void *pubkey;
};

typedef struct oqsx_key_st OQSX_KEY;

int oqs_set_nid(char* tlsname, int nid);
OQSX_KEY *oqsx_key_new(OSSL_LIB_CTX *libctx, char* oqs_name, char* tls_name, int is_kem, const char *propq, int bit_security);
int oqsx_key_allocate_keymaterial(OQSX_KEY *key);
void oqsx_key_free(OQSX_KEY *key);
int oqsx_key_up_ref(OQSX_KEY *key);
int oqsx_key_gen(OQSX_KEY *key);
OQSX_KEY *oqsx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *libctx, const char *propq);
OQSX_KEY *oqsx_key_from_x509pubkey(const X509_PUBKEY *xpk, OSSL_LIB_CTX *libctx, const char *propq);

/* Backend support */
int oqsx_public_from_private(OQSX_KEY *key);
int oqsx_key_fromdata(OQSX_KEY *oqsxk, const OSSL_PARAM params[],
                     int include_private);
int oqsx_key_parambits(OQSX_KEY *k);
int oqsx_key_maxsize(OQSX_KEY *k);
void oqsx_key_set0_libctx(OQSX_KEY *key, OSSL_LIB_CTX *libctx);

/* Function prototypes */

extern const OSSL_DISPATCH oqs_generic_kem_functions[];
extern const OSSL_DISPATCH oqs_hybrid_kem_functions[];
extern const OSSL_DISPATCH oqs_signature_functions[];

///// OQS_TEMPLATE_FRAGMENT_ENDECODER_FUNCTIONS_START
extern const OSSL_DISPATCH oqs_dilithium2_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_dilithium2_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_dilithium2_decoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_dilithium3_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_dilithium3_decoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_dilithium5_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_dilithium5_decoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_aes_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_aes_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_aes_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_aes_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_aes_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_aes_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_dilithium2_aes_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_dilithium2_aes_decoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_aes_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_aes_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_aes_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_aes_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_aes_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_aes_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_dilithium3_aes_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_dilithium3_aes_decoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_aes_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_aes_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_aes_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_aes_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_aes_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_aes_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_dilithium5_aes_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_dilithium5_aes_decoder_functions[];
extern const OSSL_DISPATCH oqs_falcon512_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_falcon512_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_falcon512_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_falcon512_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_falcon512_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_falcon512_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_falcon512_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_falcon512_decoder_functions[];
extern const OSSL_DISPATCH oqs_falcon1024_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_falcon1024_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_falcon1024_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_falcon1024_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_falcon1024_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_falcon1024_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_falcon1024_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_falcon1024_decoder_functions[];
extern const OSSL_DISPATCH oqs_picnicl1full_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_picnicl1full_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_picnicl1full_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_picnicl1full_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_picnicl1full_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_picnicl1full_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_picnicl1full_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_picnicl1full_decoder_functions[];
extern const OSSL_DISPATCH oqs_picnic3l1_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_picnic3l1_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_picnic3l1_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_picnic3l1_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_picnic3l1_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_picnic3l1_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_picnic3l1_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_picnic3l1_decoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowIclassic_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowIclassic_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowIclassic_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowIclassic_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowIclassic_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowIclassic_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_rainbowIclassic_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_rainbowIclassic_decoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowVclassic_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowVclassic_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowVclassic_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowVclassic_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowVclassic_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_rainbowVclassic_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_rainbowVclassic_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_rainbowVclassic_decoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsharaka128frobust_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsharaka128frobust_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsharaka128frobust_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsharaka128frobust_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsharaka128frobust_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsharaka128frobust_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_sphincsharaka128frobust_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_sphincsharaka128frobust_decoder_functions[];
extern const OSSL_DISPATCH oqs_sphincssha256128frobust_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincssha256128frobust_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincssha256128frobust_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincssha256128frobust_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincssha256128frobust_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincssha256128frobust_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_sphincssha256128frobust_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_sphincssha256128frobust_decoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsshake256128frobust_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsshake256128frobust_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsshake256128frobust_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsshake256128frobust_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsshake256128frobust_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH oqs_sphincsshake256128frobust_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_sphincsshake256128frobust_decoder_functions[];
extern const OSSL_DISPATCH oqs_SubjectPublicKeyInfo_der_to_sphincsshake256128frobust_decoder_functions[];
///// OQS_TEMPLATE_FRAGMENT_ENDECODER_FUNCTIONS_END

///// OQS_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_START
extern const OSSL_DISPATCH oqs_dilithium2_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium2_aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium3_aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_dilithium5_aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_falcon512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_falcon1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_picnicl1full_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_picnic3l1_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_rainbowIclassic_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_rainbowVclassic_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sphincsharaka128frobust_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sphincssha256128frobust_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sphincsshake256128frobust_keymgmt_functions[];

extern const OSSL_DISPATCH oqs_frodo640aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo640shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo976aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo976shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo1344aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_frodo1344shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hps2048509_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hps2048677_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hps4096821_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntru_hrss701_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_lightsaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_saber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_firesaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sidhp751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sikep751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_bikel1_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_bikel3_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber90s512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber90s768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_kyber90s1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_hqc128_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_hqc192_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_hqc256_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntrulpr653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntrulpr761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntrulpr857_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ntrulpr1277_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sntrup653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sntrup761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sntrup857_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_sntrup1277_keymgmt_functions[];

extern const OSSL_DISPATCH oqs_ecp_frodo640aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_frodo640shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_frodo976aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_frodo976shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_frodo1344aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_frodo1344shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntru_hps2048509_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntru_hps2048677_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntru_hps4096821_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntru_hrss701_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_lightsaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_saber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_firesaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sidhp434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sidhp503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sidhp610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sidhp751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sikep434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sikep503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sikep610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sikep751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_bikel1_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_bikel3_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber90s512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber90s768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_kyber90s1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_hqc128_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_hqc192_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_hqc256_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntrulpr653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntrulpr761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntrulpr857_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_ntrulpr1277_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sntrup653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sntrup761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sntrup857_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecp_sntrup1277_keymgmt_functions[];

extern const OSSL_DISPATCH oqs_ecx_frodo640aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_frodo640shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_frodo976aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_frodo976shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_frodo1344aes_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_frodo1344shake_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntru_hps2048509_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntru_hps2048677_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntru_hps4096821_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntru_hrss701_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_lightsaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_saber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_firesaber_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sidhp434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sidhp503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sidhp610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sidhp751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sikep434_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sikep503_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sikep610_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sikep751_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_bikel1_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_bikel3_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber90s512_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber90s768_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_kyber90s1024_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_hqc128_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_hqc192_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_hqc256_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntrulpr653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntrulpr761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntrulpr857_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_ntrulpr1277_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sntrup653_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sntrup761_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sntrup857_keymgmt_functions[];
extern const OSSL_DISPATCH oqs_ecx_sntrup1277_keymgmt_functions[];
///// OQS_TEMPLATE_FRAGMENT_ALG_FUNCTIONS_END

/* BIO function declarations */
int oqs_prov_bio_from_dispatch(const OSSL_DISPATCH *fns);

OSSL_CORE_BIO *oqs_prov_bio_new_file(const char *filename, const char *mode);
OSSL_CORE_BIO *oqs_prov_bio_new_membuf(const char *filename, int len);
int oqs_prov_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read);
int oqs_prov_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                           size_t *written);
int oqs_prov_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size);
int oqs_prov_bio_puts(OSSL_CORE_BIO *bio, const char *str);
int oqs_prov_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr);
int oqs_prov_bio_up_ref(OSSL_CORE_BIO *bio);
int oqs_prov_bio_free(OSSL_CORE_BIO *bio);
int oqs_prov_bio_vprintf(OSSL_CORE_BIO *bio, const char *format, va_list ap);
int oqs_prov_bio_printf(OSSL_CORE_BIO *bio, const char *format, ...);

BIO_METHOD *oqs_bio_prov_init_bio_method(void);
BIO *oqs_bio_new_from_core_bio(PROV_OQS_CTX *provctx, OSSL_CORE_BIO *corebio);

#endif
