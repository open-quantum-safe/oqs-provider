// SPDX-License-Identifier: Apache-2.0 AND MIT

/* 
 * OQS OpenSSL 3 provider encoders
 * 
 * Code strongly inspired by OpenSSL default provider.
 *
 */

#ifndef ENCODER_PROVIDER
# error Macro ENCODER_PROVIDER undefined
#endif

#define ENCODER_STRUCTURE_type_specific_keypair         "type-specific"
#define ENCODER_STRUCTURE_type_specific_params          "type-specific"
#define ENCODER_STRUCTURE_type_specific                 "type-specific"
#define ENCODER_STRUCTURE_type_specific_no_pub          "type-specific"
#define ENCODER_STRUCTURE_PKCS8                         "pkcs8"
#define ENCODER_STRUCTURE_SubjectPublicKeyInfo          "SubjectPublicKeyInfo"
#define ENCODER_STRUCTURE_PrivateKeyInfo                "PrivateKeyInfo"
#define ENCODER_STRUCTURE_EncryptedPrivateKeyInfo       "EncryptedPrivateKeyInfo"
#define ENCODER_STRUCTURE_PKCS1                         "pkcs1"
#define ENCODER_STRUCTURE_PKCS3                         "pkcs3"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define ENCODER_TEXT(_name, _sym)                                \
    { _name,                                                            \
      "provider=" ENCODER_PROVIDER ",output=text",      \
      (oqs_##_sym##_to_text_encoder_functions) }
#define ENCODER(_name, _sym, _fips, _output)                            \
    { _name,                                                            \
      "provider=" ENCODER_PROVIDER ",output=" #_output, \
      (oqs_##_sym##_to_##_output##_encoder_functions) }

#define ENCODER_w_structure(_name, _sym, _output, _structure)    \
    { _name,                                                            \
      "provider=" ENCODER_PROVIDER ",output=" #_output  \
      ",structure=" ENCODER_STRUCTURE_##_structure,                     \
      (oqs_##_sym##_to_##_structure##_##_output##_encoder_functions) }

/*
 * Entries for human text "encoders"
 */

/*
 * Entries for key type specific output formats.  The structure name on these
 * is the same as the key type name.  This allows us to say something like:
 *
 * To replace i2d_{TYPE}PrivateKey(), i2d_{TYPE}PublicKey() and
 * i2d_{TYPE}Params(), use OSSL_ENCODER functions with an OSSL_ENCODER_CTX
 * created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER", "type-specific",
 *                                   NULL, NULL);
 *
 * To replace PEM_write_bio_{TYPE}PrivateKey(), PEM_write_bio_{TYPE}PublicKey()
 * and PEM_write_bio_{TYPE}Params(), use OSSL_ENCODER functions with an
 * OSSL_ENCODER_CTX created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", "type-specific",
 *                                   NULL, NULL);
 *
 * We only implement those for which there are current i2d_ and PEM_write_bio
 * implementations.
 */

/*
 * Entries for PKCS#8 and SubjectPublicKeyInfo.
 * The "der" ones are added convenience for any user that wants to use
 * OSSL_ENCODER directly.
 * The "pem" ones also support PEM_write_bio_PrivateKey() and
 * PEM_write_bio_PUBKEY().
 */

///// OQS_TEMPLATE_FRAGMENT_MAKE_START
ENCODER_w_structure("dilithium2", dilithium2, der, PrivateKeyInfo),
ENCODER_w_structure("dilithium2", dilithium2, pem, PrivateKeyInfo),
ENCODER_w_structure("dilithium2", dilithium2, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium2", dilithium2, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium2", dilithium2, der, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium2", dilithium2, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p256_dilithium2", p256_dilithium2, der, PrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, pem, SubjectPublicKeyInfo),ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, der, PrivateKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, pem, PrivateKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, der, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p384_dilithium3", p384_dilithium3, der, PrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, pem, PrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, der, PrivateKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, pem, PrivateKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, der, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p521_dilithium5", p521_dilithium5, der, PrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, pem, PrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium2_aes", dilithium2_aes, der, PrivateKeyInfo),
ENCODER_w_structure("dilithium2_aes", dilithium2_aes, pem, PrivateKeyInfo),
ENCODER_w_structure("dilithium2_aes", dilithium2_aes, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium2_aes", dilithium2_aes, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium2_aes", dilithium2_aes, der, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium2_aes", dilithium2_aes, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p256_dilithium2_aes", p256_dilithium2_aes, der, PrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2_aes", p256_dilithium2_aes, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2_aes", p256_dilithium2_aes, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2_aes", p256_dilithium2_aes, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2_aes", p256_dilithium2_aes, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_dilithium2_aes", p256_dilithium2_aes, pem, SubjectPublicKeyInfo),ENCODER_w_structure("rsa3072_dilithium2_aes", rsa3072_dilithium2_aes, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2_aes", rsa3072_dilithium2_aes, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2_aes", rsa3072_dilithium2_aes, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2_aes", rsa3072_dilithium2_aes, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2_aes", rsa3072_dilithium2_aes, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2_aes", rsa3072_dilithium2_aes, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium3_aes", dilithium3_aes, der, PrivateKeyInfo),
ENCODER_w_structure("dilithium3_aes", dilithium3_aes, pem, PrivateKeyInfo),
ENCODER_w_structure("dilithium3_aes", dilithium3_aes, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium3_aes", dilithium3_aes, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium3_aes", dilithium3_aes, der, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium3_aes", dilithium3_aes, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p384_dilithium3_aes", p384_dilithium3_aes, der, PrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3_aes", p384_dilithium3_aes, pem, PrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3_aes", p384_dilithium3_aes, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3_aes", p384_dilithium3_aes, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3_aes", p384_dilithium3_aes, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p384_dilithium3_aes", p384_dilithium3_aes, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium5_aes", dilithium5_aes, der, PrivateKeyInfo),
ENCODER_w_structure("dilithium5_aes", dilithium5_aes, pem, PrivateKeyInfo),
ENCODER_w_structure("dilithium5_aes", dilithium5_aes, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium5_aes", dilithium5_aes, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium5_aes", dilithium5_aes, der, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium5_aes", dilithium5_aes, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p521_dilithium5_aes", p521_dilithium5_aes, der, PrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5_aes", p521_dilithium5_aes, pem, PrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5_aes", p521_dilithium5_aes, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5_aes", p521_dilithium5_aes, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5_aes", p521_dilithium5_aes, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p521_dilithium5_aes", p521_dilithium5_aes, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("falcon512", falcon512, der, PrivateKeyInfo),
ENCODER_w_structure("falcon512", falcon512, pem, PrivateKeyInfo),
ENCODER_w_structure("falcon512", falcon512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("falcon512", falcon512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("falcon512", falcon512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("falcon512", falcon512, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p256_falcon512", p256_falcon512, der, PrivateKeyInfo),
ENCODER_w_structure("p256_falcon512", p256_falcon512, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_falcon512", p256_falcon512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_falcon512", p256_falcon512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_falcon512", p256_falcon512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_falcon512", p256_falcon512, pem, SubjectPublicKeyInfo),ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, der, PrivateKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, pem, PrivateKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p521_falcon1024", p521_falcon1024, der, PrivateKeyInfo),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, pem, PrivateKeyInfo),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("picnicl1full", picnicl1full, der, PrivateKeyInfo),
ENCODER_w_structure("picnicl1full", picnicl1full, pem, PrivateKeyInfo),
ENCODER_w_structure("picnicl1full", picnicl1full, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("picnicl1full", picnicl1full, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("picnicl1full", picnicl1full, der, SubjectPublicKeyInfo),
ENCODER_w_structure("picnicl1full", picnicl1full, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p256_picnicl1full", p256_picnicl1full, der, PrivateKeyInfo),
ENCODER_w_structure("p256_picnicl1full", p256_picnicl1full, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_picnicl1full", p256_picnicl1full, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_picnicl1full", p256_picnicl1full, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_picnicl1full", p256_picnicl1full, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_picnicl1full", p256_picnicl1full, pem, SubjectPublicKeyInfo),ENCODER_w_structure("rsa3072_picnicl1full", rsa3072_picnicl1full, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_picnicl1full", rsa3072_picnicl1full, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_picnicl1full", rsa3072_picnicl1full, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_picnicl1full", rsa3072_picnicl1full, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_picnicl1full", rsa3072_picnicl1full, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_picnicl1full", rsa3072_picnicl1full, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("picnic3l1", picnic3l1, der, PrivateKeyInfo),
ENCODER_w_structure("picnic3l1", picnic3l1, pem, PrivateKeyInfo),
ENCODER_w_structure("picnic3l1", picnic3l1, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("picnic3l1", picnic3l1, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("picnic3l1", picnic3l1, der, SubjectPublicKeyInfo),
ENCODER_w_structure("picnic3l1", picnic3l1, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p256_picnic3l1", p256_picnic3l1, der, PrivateKeyInfo),
ENCODER_w_structure("p256_picnic3l1", p256_picnic3l1, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_picnic3l1", p256_picnic3l1, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_picnic3l1", p256_picnic3l1, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_picnic3l1", p256_picnic3l1, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_picnic3l1", p256_picnic3l1, pem, SubjectPublicKeyInfo),ENCODER_w_structure("rsa3072_picnic3l1", rsa3072_picnic3l1, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_picnic3l1", rsa3072_picnic3l1, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_picnic3l1", rsa3072_picnic3l1, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_picnic3l1", rsa3072_picnic3l1, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_picnic3l1", rsa3072_picnic3l1, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_picnic3l1", rsa3072_picnic3l1, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("rainbowVclassic", rainbowVclassic, der, PrivateKeyInfo),
ENCODER_w_structure("rainbowVclassic", rainbowVclassic, pem, PrivateKeyInfo),
ENCODER_w_structure("rainbowVclassic", rainbowVclassic, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rainbowVclassic", rainbowVclassic, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rainbowVclassic", rainbowVclassic, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rainbowVclassic", rainbowVclassic, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p521_rainbowVclassic", p521_rainbowVclassic, der, PrivateKeyInfo),
ENCODER_w_structure("p521_rainbowVclassic", p521_rainbowVclassic, pem, PrivateKeyInfo),
ENCODER_w_structure("p521_rainbowVclassic", p521_rainbowVclassic, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_rainbowVclassic", p521_rainbowVclassic, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_rainbowVclassic", p521_rainbowVclassic, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p521_rainbowVclassic", p521_rainbowVclassic, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("sphincsharaka128frobust", sphincsharaka128frobust, der, PrivateKeyInfo),
ENCODER_w_structure("sphincsharaka128frobust", sphincsharaka128frobust, pem, PrivateKeyInfo),
ENCODER_w_structure("sphincsharaka128frobust", sphincsharaka128frobust, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincsharaka128frobust", sphincsharaka128frobust, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincsharaka128frobust", sphincsharaka128frobust, der, SubjectPublicKeyInfo),
ENCODER_w_structure("sphincsharaka128frobust", sphincsharaka128frobust, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p256_sphincsharaka128frobust", p256_sphincsharaka128frobust, der, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincsharaka128frobust", p256_sphincsharaka128frobust, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincsharaka128frobust", p256_sphincsharaka128frobust, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincsharaka128frobust", p256_sphincsharaka128frobust, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincsharaka128frobust", p256_sphincsharaka128frobust, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_sphincsharaka128frobust", p256_sphincsharaka128frobust, pem, SubjectPublicKeyInfo),ENCODER_w_structure("rsa3072_sphincsharaka128frobust", rsa3072_sphincsharaka128frobust, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsharaka128frobust", rsa3072_sphincsharaka128frobust, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsharaka128frobust", rsa3072_sphincsharaka128frobust, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsharaka128frobust", rsa3072_sphincsharaka128frobust, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsharaka128frobust", rsa3072_sphincsharaka128frobust, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_sphincsharaka128frobust", rsa3072_sphincsharaka128frobust, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("sphincssha256128frobust", sphincssha256128frobust, der, PrivateKeyInfo),
ENCODER_w_structure("sphincssha256128frobust", sphincssha256128frobust, pem, PrivateKeyInfo),
ENCODER_w_structure("sphincssha256128frobust", sphincssha256128frobust, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincssha256128frobust", sphincssha256128frobust, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincssha256128frobust", sphincssha256128frobust, der, SubjectPublicKeyInfo),
ENCODER_w_structure("sphincssha256128frobust", sphincssha256128frobust, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p256_sphincssha256128frobust", p256_sphincssha256128frobust, der, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha256128frobust", p256_sphincssha256128frobust, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha256128frobust", p256_sphincssha256128frobust, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha256128frobust", p256_sphincssha256128frobust, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha256128frobust", p256_sphincssha256128frobust, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_sphincssha256128frobust", p256_sphincssha256128frobust, pem, SubjectPublicKeyInfo),ENCODER_w_structure("rsa3072_sphincssha256128frobust", rsa3072_sphincssha256128frobust, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha256128frobust", rsa3072_sphincssha256128frobust, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha256128frobust", rsa3072_sphincssha256128frobust, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha256128frobust", rsa3072_sphincssha256128frobust, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha256128frobust", rsa3072_sphincssha256128frobust, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha256128frobust", rsa3072_sphincssha256128frobust, pem, SubjectPublicKeyInfo),
ENCODER_w_structure("sphincsshake256128frobust", sphincsshake256128frobust, der, PrivateKeyInfo),
ENCODER_w_structure("sphincsshake256128frobust", sphincsshake256128frobust, pem, PrivateKeyInfo),
ENCODER_w_structure("sphincsshake256128frobust", sphincsshake256128frobust, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincsshake256128frobust", sphincsshake256128frobust, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincsshake256128frobust", sphincsshake256128frobust, der, SubjectPublicKeyInfo),
ENCODER_w_structure("sphincsshake256128frobust", sphincsshake256128frobust, pem, SubjectPublicKeyInfo),ENCODER_w_structure("p256_sphincsshake256128frobust", p256_sphincsshake256128frobust, der, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincsshake256128frobust", p256_sphincsshake256128frobust, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincsshake256128frobust", p256_sphincsshake256128frobust, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincsshake256128frobust", p256_sphincsshake256128frobust, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincsshake256128frobust", p256_sphincsshake256128frobust, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_sphincsshake256128frobust", p256_sphincsshake256128frobust, pem, SubjectPublicKeyInfo),ENCODER_w_structure("rsa3072_sphincsshake256128frobust", rsa3072_sphincsshake256128frobust, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsshake256128frobust", rsa3072_sphincsshake256128frobust, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsshake256128frobust", rsa3072_sphincsshake256128frobust, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsshake256128frobust", rsa3072_sphincsshake256128frobust, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsshake256128frobust", rsa3072_sphincsshake256128frobust, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_sphincsshake256128frobust", rsa3072_sphincsshake256128frobust, pem, SubjectPublicKeyInfo),
///// OQS_TEMPLATE_FRAGMENT_MAKE_END

