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
#ifdef OQS_ENABLE_SIG_dilithium_2
ENCODER_w_structure("dilithium2", dilithium2, der, PrivateKeyInfo),
ENCODER_w_structure("dilithium2", dilithium2, pem, PrivateKeyInfo),
ENCODER_w_structure("dilithium2", dilithium2, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium2", dilithium2, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium2", dilithium2, der, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium2", dilithium2, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("dilithium2", dilithium2),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, der, PrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_dilithium2", p256_dilithium2, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p256_dilithium2", p256_dilithium2),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_dilithium2", rsa3072_dilithium2, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("rsa3072_dilithium2", rsa3072_dilithium2),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3
ENCODER_w_structure("dilithium3", dilithium3, der, PrivateKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, pem, PrivateKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, der, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium3", dilithium3, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("dilithium3", dilithium3),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, der, PrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, pem, PrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p384_dilithium3", p384_dilithium3, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p384_dilithium3", p384_dilithium3),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5
ENCODER_w_structure("dilithium5", dilithium5, der, PrivateKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, pem, PrivateKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, der, SubjectPublicKeyInfo),
ENCODER_w_structure("dilithium5", dilithium5, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("dilithium5", dilithium5),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, der, PrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, pem, PrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p521_dilithium5", p521_dilithium5, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p521_dilithium5", p521_dilithium5),
#endif
#ifdef OQS_ENABLE_SIG_falcon_512
ENCODER_w_structure("falcon512", falcon512, der, PrivateKeyInfo),
ENCODER_w_structure("falcon512", falcon512, pem, PrivateKeyInfo),
ENCODER_w_structure("falcon512", falcon512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("falcon512", falcon512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("falcon512", falcon512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("falcon512", falcon512, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("falcon512", falcon512),
ENCODER_w_structure("p256_falcon512", p256_falcon512, der, PrivateKeyInfo),
ENCODER_w_structure("p256_falcon512", p256_falcon512, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_falcon512", p256_falcon512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_falcon512", p256_falcon512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_falcon512", p256_falcon512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_falcon512", p256_falcon512, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p256_falcon512", p256_falcon512),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_falcon512", rsa3072_falcon512, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("rsa3072_falcon512", rsa3072_falcon512),
#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
ENCODER_w_structure("falcon1024", falcon1024, der, PrivateKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, pem, PrivateKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("falcon1024", falcon1024, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("falcon1024", falcon1024),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, der, PrivateKeyInfo),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, pem, PrivateKeyInfo),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p521_falcon1024", p521_falcon1024, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p521_falcon1024", p521_falcon1024),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128f_simple
ENCODER_w_structure("sphincssha2128fsimple", sphincssha2128fsimple, der, PrivateKeyInfo),
ENCODER_w_structure("sphincssha2128fsimple", sphincssha2128fsimple, pem, PrivateKeyInfo),
ENCODER_w_structure("sphincssha2128fsimple", sphincssha2128fsimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincssha2128fsimple", sphincssha2128fsimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincssha2128fsimple", sphincssha2128fsimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("sphincssha2128fsimple", sphincssha2128fsimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("sphincssha2128fsimple", sphincssha2128fsimple),
ENCODER_w_structure("p256_sphincssha2128fsimple", p256_sphincssha2128fsimple, der, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha2128fsimple", p256_sphincssha2128fsimple, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha2128fsimple", p256_sphincssha2128fsimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha2128fsimple", p256_sphincssha2128fsimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha2128fsimple", p256_sphincssha2128fsimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_sphincssha2128fsimple", p256_sphincssha2128fsimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p256_sphincssha2128fsimple", p256_sphincssha2128fsimple),
ENCODER_w_structure("rsa3072_sphincssha2128fsimple", rsa3072_sphincssha2128fsimple, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha2128fsimple", rsa3072_sphincssha2128fsimple, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha2128fsimple", rsa3072_sphincssha2128fsimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha2128fsimple", rsa3072_sphincssha2128fsimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha2128fsimple", rsa3072_sphincssha2128fsimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha2128fsimple", rsa3072_sphincssha2128fsimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("rsa3072_sphincssha2128fsimple", rsa3072_sphincssha2128fsimple),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128s_simple
ENCODER_w_structure("sphincssha2128ssimple", sphincssha2128ssimple, der, PrivateKeyInfo),
ENCODER_w_structure("sphincssha2128ssimple", sphincssha2128ssimple, pem, PrivateKeyInfo),
ENCODER_w_structure("sphincssha2128ssimple", sphincssha2128ssimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincssha2128ssimple", sphincssha2128ssimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincssha2128ssimple", sphincssha2128ssimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("sphincssha2128ssimple", sphincssha2128ssimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("sphincssha2128ssimple", sphincssha2128ssimple),
ENCODER_w_structure("p256_sphincssha2128ssimple", p256_sphincssha2128ssimple, der, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha2128ssimple", p256_sphincssha2128ssimple, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha2128ssimple", p256_sphincssha2128ssimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha2128ssimple", p256_sphincssha2128ssimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincssha2128ssimple", p256_sphincssha2128ssimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_sphincssha2128ssimple", p256_sphincssha2128ssimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p256_sphincssha2128ssimple", p256_sphincssha2128ssimple),
ENCODER_w_structure("rsa3072_sphincssha2128ssimple", rsa3072_sphincssha2128ssimple, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha2128ssimple", rsa3072_sphincssha2128ssimple, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha2128ssimple", rsa3072_sphincssha2128ssimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha2128ssimple", rsa3072_sphincssha2128ssimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha2128ssimple", rsa3072_sphincssha2128ssimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_sphincssha2128ssimple", rsa3072_sphincssha2128ssimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("rsa3072_sphincssha2128ssimple", rsa3072_sphincssha2128ssimple),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_192f_simple
ENCODER_w_structure("sphincssha2192fsimple", sphincssha2192fsimple, der, PrivateKeyInfo),
ENCODER_w_structure("sphincssha2192fsimple", sphincssha2192fsimple, pem, PrivateKeyInfo),
ENCODER_w_structure("sphincssha2192fsimple", sphincssha2192fsimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincssha2192fsimple", sphincssha2192fsimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincssha2192fsimple", sphincssha2192fsimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("sphincssha2192fsimple", sphincssha2192fsimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("sphincssha2192fsimple", sphincssha2192fsimple),
ENCODER_w_structure("p384_sphincssha2192fsimple", p384_sphincssha2192fsimple, der, PrivateKeyInfo),
ENCODER_w_structure("p384_sphincssha2192fsimple", p384_sphincssha2192fsimple, pem, PrivateKeyInfo),
ENCODER_w_structure("p384_sphincssha2192fsimple", p384_sphincssha2192fsimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_sphincssha2192fsimple", p384_sphincssha2192fsimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_sphincssha2192fsimple", p384_sphincssha2192fsimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p384_sphincssha2192fsimple", p384_sphincssha2192fsimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p384_sphincssha2192fsimple", p384_sphincssha2192fsimple),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_shake_128f_simple
ENCODER_w_structure("sphincsshake128fsimple", sphincsshake128fsimple, der, PrivateKeyInfo),
ENCODER_w_structure("sphincsshake128fsimple", sphincsshake128fsimple, pem, PrivateKeyInfo),
ENCODER_w_structure("sphincsshake128fsimple", sphincsshake128fsimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincsshake128fsimple", sphincsshake128fsimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("sphincsshake128fsimple", sphincsshake128fsimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("sphincsshake128fsimple", sphincsshake128fsimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("sphincsshake128fsimple", sphincsshake128fsimple),
ENCODER_w_structure("p256_sphincsshake128fsimple", p256_sphincsshake128fsimple, der, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincsshake128fsimple", p256_sphincsshake128fsimple, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_sphincsshake128fsimple", p256_sphincsshake128fsimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincsshake128fsimple", p256_sphincsshake128fsimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_sphincsshake128fsimple", p256_sphincsshake128fsimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_sphincsshake128fsimple", p256_sphincsshake128fsimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p256_sphincsshake128fsimple", p256_sphincsshake128fsimple),
ENCODER_w_structure("rsa3072_sphincsshake128fsimple", rsa3072_sphincsshake128fsimple, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsshake128fsimple", rsa3072_sphincsshake128fsimple, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsshake128fsimple", rsa3072_sphincsshake128fsimple, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsshake128fsimple", rsa3072_sphincsshake128fsimple, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_sphincsshake128fsimple", rsa3072_sphincsshake128fsimple, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_sphincsshake128fsimple", rsa3072_sphincsshake128fsimple, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("rsa3072_sphincsshake128fsimple", rsa3072_sphincsshake128fsimple),
#endif
///// OQS_TEMPLATE_FRAGMENT_MAKE_END

