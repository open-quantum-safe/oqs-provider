// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <string.h>

#include "oqs_prov.h"
#include "test_common.h"

#define MAX_DUMMY_ENTROPY_BUFFERLEN 0x100000

/** \brief The info about classical elements needed. */
struct ClassicalInfo {
    /** \brief Name label. */
    const char *name;

    /** \brief The public key length, in bytes. */
    size_t pubkey_len;

    /** \brief The private key length, in bytes. */
    size_t privkey_len;

    /** \brief The shared secret length, in bytes. */
    size_t sec_len;

    /** \brief The signature length, in bytes. */
    size_t sig_len;
};

static const struct ClassicalInfo info_classical[] = {
    {"p256", 65, 121, 32, 72},      {"SecP256r1", 65, 121, 32, 72},
    {"p384", 97, 167, 48, 104},     {"p521", 133, 223, 66, 141},
    {"bp256", 65, 122, 32, 72},     {"bp384", 97, 171, 48, 104},
    {"rsa3072", 398, 1770, 0, 384}, {"pss3072", 398, 1770, 0, 384},
    {"rsa2048", 270, 1193, 0, 256}, {"pss2048", 270, 1193, 0, 256},
    {"ed25519", 32, 32, 0, 67},     {"ed448", 57, 57, 0, 117},
    {"x25519", 32, 32, 32, 0},      {"X25519", 32, 32, 32, 0},
    {"x448", 56, 56, 56, 0},
};

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;

/** \brief Loads OpenSSL's 'TEST-RAND' deterministic pseudorandom generator for
 * the given library context
 *
 * \param libctx Library context.
 *
 * \return 1 if the configuration is successfully loaded, else 0. */
static int oqs_load_det_pseudorandom_generator(OSSL_LIB_CTX *libctx) {
    OSSL_PARAM params[2], *p = params;
    unsigned char entropy[MAX_DUMMY_ENTROPY_BUFFERLEN];
    RAND_bytes(entropy, sizeof(entropy));

    if (!RAND_set_DRBG_type(libctx, "TEST-RAND", NULL, NULL, NULL)) {
        return 0;
    }

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                             entropy, sizeof(entropy));
    *p = OSSL_PARAM_construct_end();

    EVP_RAND_CTX *rctx_public = RAND_get0_public(libctx);
    if (!rctx_public) {
        return 0;
    }

    if (!EVP_RAND_CTX_set_params(rctx_public, params)) {
        return 0;
    }

    EVP_RAND_CTX *rctx_private = RAND_get0_private(libctx);
    if (!rctx_private) {
        return 0;
    }

    if (!EVP_RAND_CTX_set_params(rctx_private, params)) {
        return 0;
    }

    return 1;
}

/** \brief Resets the given library context's DRBG instances
 *
 * \param libctx Library context.
 *
 * \return 1 if the configuration is successfully restarted, else 0. */
static int oqs_reset_det_pseudorandom_generator(OSSL_LIB_CTX *libctx) {
    OSSL_PARAM params[2], *p = params;
    unsigned int strength = 256;

    // information not needed, but for RAND to reset, it needs at least one
    // param
    *p++ = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    *p = OSSL_PARAM_construct_end();

    EVP_RAND_CTX *rctx_public = RAND_get0_public(libctx);
    if (!rctx_public) {
        return 0;
    }

    EVP_RAND_uninstantiate(rctx_public);
    if (!EVP_RAND_instantiate(rctx_public, strength, 0, NULL, 0, params)) {
        return 0;
    }

    EVP_RAND_CTX *rctx_private = RAND_get0_private(libctx);
    if (!rctx_private) {
        return 0;
    }

    EVP_RAND_uninstantiate(rctx_private);
    if (!EVP_RAND_instantiate(rctx_private, strength, 0, NULL, 0, params)) {
        return 0;
    }

    return 1;
}

/** \brief Performs the expected KEM operations (KeyGen, Encaps, Decaps)
 *
 * \param kemalg_name algorithm name.
 * \param[out] key The object to hold the key pair.
 * \param[out] secenc Encaps Shared Secret Buffer .
 * \param[out] seclen Shared Secret length.
 * \param[out] secdec Decaps Shared Secret Buffer .
 * \param[out] out Encapsulation buffer.
 * \param[out] outlen Encapsulation length.
 *
 * \return 1 if the operations are successful, else 0. */
static int oqs_generate_kem_elems(const char *kemalg_name, EVP_PKEY **key,
                                  unsigned char **secenc, size_t *seclen,
                                  unsigned char **secdec, unsigned char **out,
                                  size_t *outlen) {
    int testresult = 1;
    EVP_PKEY_CTX *ctx = NULL;

    if (!oqs_reset_det_pseudorandom_generator(libctx)) {
        return 0;
    }

    // test with built-in digest only if default provider is active:
    // TBD revisit when hybrids are activated: They always need default
    // provider
    if (OSSL_PROVIDER_available(libctx, "default")) {
        testresult &= (ctx = EVP_PKEY_CTX_new_from_name(libctx, kemalg_name,
                                                        NULL)) != NULL &&
                      EVP_PKEY_keygen_init(ctx) && EVP_PKEY_generate(ctx, key);

        if (!testresult)
            goto err;
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;

        testresult &=
            (ctx = EVP_PKEY_CTX_new_from_pkey(libctx, *key, NULL)) != NULL &&
            EVP_PKEY_encapsulate_init(ctx, NULL) &&
            EVP_PKEY_encapsulate(ctx, NULL, outlen, NULL, seclen) &&
            (*out = OPENSSL_malloc(*outlen)) != NULL &&
            (*secenc = OPENSSL_malloc(*seclen)) != NULL &&
            memset(*secenc, 0x11, *seclen) != NULL &&
            (*secdec = OPENSSL_malloc(*seclen)) != NULL &&
            memset(*secdec, 0xff, *seclen) != NULL &&
            EVP_PKEY_encapsulate(ctx, *out, outlen, *secenc, seclen) &&
            EVP_PKEY_decapsulate_init(ctx, NULL) &&
            EVP_PKEY_decapsulate(ctx, *secdec, seclen, *out, *outlen) &&
            memcmp(*secenc, *secdec, *seclen) == 0;
    }

err:
    EVP_PKEY_CTX_free(ctx);
    return testresult;
}

/** \brief Performs the expected SIG operations (KeyGen, Sign, Verify)
 *
 * \param sigalg_name algorithm name.
 * \param msg Message to be signed.
 * \param msglen Message length.
 * \param[out] key The object to hold the key pair.
 * \param[out] sig Signature Buffer .
 * \param[out] siglen Signature length.
 *
 * \return 1 if the operations are successful, else 0. */
static int oqs_generate_sig_elems(const char *sigalg_name, const char *msg,
                                  size_t msglen, EVP_PKEY **key,
                                  unsigned char **sig, size_t *siglen) {
    int testresult = 1;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *mdctx = NULL;

    if (!oqs_reset_det_pseudorandom_generator(libctx)) {
        return 0;
    }

    // test with built-in digest only if default provider is active:
    // TBD revisit when hybrids are activated: They always need default
    // provider
    if (OSSL_PROVIDER_available(libctx, "default")) {
        testresult &=
            (ctx = EVP_PKEY_CTX_new_from_name(libctx, sigalg_name, NULL)) !=
                NULL &&
            EVP_PKEY_keygen_init(ctx) && EVP_PKEY_generate(ctx, key) &&
            (mdctx = EVP_MD_CTX_new()) != NULL &&
            EVP_DigestSignInit_ex(mdctx, NULL, "SHA512", libctx, NULL, *key,
                                  NULL) &&
            EVP_DigestSignUpdate(mdctx, msg, msglen) &&
            EVP_DigestSignFinal(mdctx, NULL, siglen) &&
            (*sig = OPENSSL_malloc(*siglen)) != NULL &&
            EVP_DigestSignFinal(mdctx, *sig, siglen) &&
            EVP_DigestVerifyInit_ex(mdctx, NULL, "SHA512", libctx, NULL, *key,
                                    NULL) &&
            EVP_DigestVerifyUpdate(mdctx, msg, msglen) &&
            EVP_DigestVerifyFinal(mdctx, *sig, *siglen);
    }

err:
    EVP_PKEY_CTX_free(ctx);
    EVP_MD_CTX_free(mdctx);
    return testresult;
}

/** \brief Compares the classical key pairs of two hybrid key pairs
 *
 * \param key1 A key pair.
 * \param key2 A key pair.
 *
 * \return 1 if the compare operation is successful, else 0. */
static int oqs_cmp_classical_keys(const EVP_PKEY *key1, const EVP_PKEY *key2) {
    int ret = 0;
    unsigned char *pubkey1 = NULL, *pubkey2 = NULL, *privkey1 = NULL,
                  *privkey2 = NULL;
    size_t pubkey1_len, pubkey2_len, privkey1_len, privkey2_len;

    if (get_param_octet_string(key1, OQS_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY,
                               &pubkey1, &pubkey1_len)) {
        goto out;
    }
    if (get_param_octet_string(key2, OQS_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY,
                               &pubkey2, &pubkey2_len)) {
        goto out;
    }

    if (get_param_octet_string(key1, OQS_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY,
                               &privkey1, &privkey1_len)) {
        goto out;
    }
    if (get_param_octet_string(key2, OQS_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY,
                               &privkey2, &privkey2_len)) {
        goto out;
    }
    ret = (pubkey1_len == pubkey2_len) && (privkey1_len == privkey2_len);
    if (!ret) {
        goto out;
    }
    ret &= memcmp(pubkey1, pubkey2, pubkey1_len) == 0 &&
           memcmp(privkey1, privkey2, privkey1_len) == 0;

out:
    free(pubkey1);
    free(pubkey2);
    free(privkey1);
    free(privkey2);
    return ret;
}

/** \brief Returns the index asscoiated to the 'info_classical' struct
 *
 * \param alg_name algorithm name.
 *
 * \return The associated index, or OOB in case no match is found. */
static int oqs_get_idx(const char *alg_name) {
    int idx = 0;
    char *algdup = strdup(alg_name);
    char *name = strtok(algdup, "_");

    if (strncmp(alg_name, "mldsa", 5) == 0) {
        name = strtok(NULL, "_");
    }

    while (idx < OSSL_NELEM(info_classical)) {
        if (!strncmp(name, info_classical[idx].name,
                     strlen(info_classical[idx].name)))
            break;
        idx++;
    }
    free(algdup);

    return idx;
}

/** \brief Compares the classical key pairs of two composite key pairs
 *
 * \param sigalg_name algorithm name.
 * \param key1 A key pair.
 * \param key2 A key pair.
 *
 * \return 1 if the compare operation is successful, else 0. */
static int oqs_cmp_composite_sig_keys(const char *sigalg_name,
                                      const EVP_PKEY *key1,
                                      const EVP_PKEY *key2) {
    int ret = 0, ret_rev = 0, idx;
    unsigned char *pubkey1 = NULL, *pubkey2 = NULL, *privkey1 = NULL,
                  *privkey2 = NULL;
    size_t pubkey1_len, pubkey2_len, privkey1_len, privkey2_len;

    if (get_param_octet_string(key1, OSSL_PKEY_PARAM_PUB_KEY, &pubkey1,
                               &pubkey1_len)) {
        goto out;
    }
    if (get_param_octet_string(key2, OSSL_PKEY_PARAM_PUB_KEY, &pubkey2,
                               &pubkey2_len)) {
        goto out;
    }

    if (get_param_octet_string(key1, OSSL_PKEY_PARAM_PRIV_KEY, &privkey1,
                               &privkey1_len)) {
        goto out;
    }
    if (get_param_octet_string(key2, OSSL_PKEY_PARAM_PRIV_KEY, &privkey2,
                               &privkey2_len)) {
        goto out;
    }

    if ((idx = oqs_get_idx(sigalg_name)) >= OSSL_NELEM(info_classical)) {
        goto out;
    }

    if (!((pubkey1_len == pubkey2_len) && (privkey1_len == privkey2_len))) {
        goto out;
    }

    ret = memcmp(pubkey1, pubkey2, info_classical[idx].pubkey_len) == 0 &&
          memcmp(privkey1, privkey2, info_classical[idx].privkey_len) == 0;

    ret_rev = memcmp(pubkey1 + pubkey1_len - info_classical[idx].pubkey_len,
                     pubkey2 + pubkey2_len - info_classical[idx].pubkey_len,
                     info_classical[idx].pubkey_len) == 0 &&
              memcmp(privkey1 + privkey1_len - info_classical[idx].privkey_len,
                     privkey2 + privkey2_len - info_classical[idx].privkey_len,
                     info_classical[idx].privkey_len) == 0;

out:
    free(pubkey1);
    free(pubkey2);
    free(privkey1);
    free(privkey2);
    return ret || ret_rev;
}

/** \brief Compares the classical KEM elemets of two Encaps/Decaps executions
 *
 * \param kemalg_name algorithm name.
 * \param sec1 A shared secret.
 * \param sec2 A shared secret.
 * \param seclen Shared secret length.
 * \param ct1 An encapsulation.
 * \param ct1 An encapsulation.
 * \param ctlen Encapsulation lentgh.
 *
 * \return 1 if the compare operation is successful, else 0. */
static int oqs_cmp_kem_elems(const char *kemalg_name, const unsigned char *sec1,
                             const unsigned char *sec2, size_t seclen,
                             const unsigned char *ct1, const unsigned char *ct2,
                             size_t ctlen) {
    int ret = 1, ret_rev = 1, idx = 0;

    if ((idx = oqs_get_idx(kemalg_name)) >= OSSL_NELEM(info_classical)) {
        return 0;
    }

    ret_rev &= memcmp(sec1 + seclen - info_classical[idx].sec_len,
                      sec2 + seclen - info_classical[idx].sec_len,
                      info_classical[idx].sec_len) == 0 &&
               memcmp(ct1 + ctlen - info_classical[idx].pubkey_len,
                      ct2 + ctlen - info_classical[idx].pubkey_len,
                      info_classical[idx].pubkey_len) == 0;

    ret &= memcmp(sec1, sec2, info_classical[idx].sec_len) == 0 &&
           memcmp(ct1, ct2, info_classical[idx].pubkey_len) == 0;

    return ret || ret_rev;
}

/** \brief Compares the classical SIG elemets of two Sign executions
 *
 * \param sigalg_name algorithm name.
 * \param sig1 A signature.
 * \param sig1len Signature length.
 * \param sig2 A signature.
 * \param sig2len Signature length.
 *
 * \return 1 if the compare operation is successful, else 0. */
static int oqs_cmp_sig_elems(const char *sigalg_name, const unsigned char *sig1,
                             size_t sig1len, const unsigned char *sig2,
                             size_t sig2len) {
    int ret = 1, ret_rev = 1, idx;

    if ((idx = oqs_get_idx(sigalg_name)) >= OSSL_NELEM(info_classical)) {
        return 0;
    }

    ret_rev &= memcmp(sig1 + sig1len - info_classical[idx].sig_len,
                      sig2 + sig2len - info_classical[idx].sig_len,
                      info_classical[idx].sig_len) == 0;
    ret &= memcmp(sig1, sig2, info_classical[idx].sig_len) == 0;

    return ret || ret_rev;
}

/** \brief Executes the complete comparison of two KEM executions
 *
 * \param kemalg_name algorithm name.
 *
 * \return 1 if the compare operation is successful, else 0. */
static int test_oqs_kems_libctx(const char *kemalg_name) {
    EVP_PKEY *key1 = NULL, *key2 = NULL;
    unsigned char *out1 = NULL, *out2 = NULL;
    unsigned char *secenc1 = NULL, *secenc2 = NULL;
    unsigned char *secdec1 = NULL, *secdec2 = NULL;
    size_t outlen1, outlen2, seclen1, seclen2;

    int testresult = 1;

    if (!alg_is_enabled(kemalg_name)) {
        printf("Not testing disabled algorithm %s.\n", kemalg_name);
        return 1;
    }
    testresult &= oqs_generate_kem_elems(kemalg_name, &key1, &secenc1, &seclen1,
                                         &secdec1, &out1, &outlen1) &&
                  oqs_generate_kem_elems(kemalg_name, &key2, &secenc2, &seclen2,
                                         &secdec2, &out2, &outlen2);

    testresult &= oqs_cmp_classical_keys(key1, key2) && (seclen1 == seclen2) &&
                  (outlen1 == outlen2);
    if (!testresult)
        goto err;

    testresult &= oqs_cmp_kem_elems(kemalg_name, secenc1, secenc2, seclen1,
                                    out1, out2, outlen1);

err:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    OPENSSL_free(out1);
    OPENSSL_free(out2);
    OPENSSL_free(secenc1);
    OPENSSL_free(secenc2);
    OPENSSL_free(secdec1);
    OPENSSL_free(secdec2);
    return testresult;
}

/** \brief Executes the complete comparison of two SIG executions
 *
 * \param sigalg_name algorithm name.
 *
 * \return 1 if the compare operation is successful, else 0. */
static int test_oqs_sigs_libctx(const char *sigalg_name) {
    EVP_PKEY *key1 = NULL, *key2 = NULL;
    const char msg[] = "The quick brown fox jumps over... you know what";
    unsigned char *sig1 = NULL, *sig2 = NULL;
    size_t sig1len, sig2len;

    int testresult = 1;

    if (!alg_is_enabled(sigalg_name)) {
        printf("Not testing disabled algorithm %s.\n", sigalg_name);
        return 1;
    }
    testresult &= oqs_generate_sig_elems(sigalg_name, msg, sizeof(msg), &key1,
                                         &sig1, &sig1len) &&
                  oqs_generate_sig_elems(sigalg_name, msg, sizeof(msg), &key2,
                                         &sig2, &sig2len);

    if (is_signature_algorithm_hybrid(sigalg_name)) {
        testresult &= oqs_cmp_classical_keys(key1, key2);
    } else {
        testresult &= oqs_cmp_composite_sig_keys(sigalg_name, key1, key2);
    }

    if (!testresult)
        goto err;

    testresult &= oqs_cmp_sig_elems(sigalg_name, sig1, sig1len, sig2, sig2len);

err:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    OPENSSL_free(sig1);
    OPENSSL_free(sig2);
    return testresult;
}

#define nelem(a) (sizeof(a) / sizeof((a)[0]))

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0, query_nocache;
    OSSL_PROVIDER *oqsprov = NULL;
    const OSSL_ALGORITHM *kemalgs, *sigalgs;

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    oqs_load_det_pseudorandom_generator(libctx);
    load_oqs_provider(libctx, modulename, configfile);

    oqsprov = OSSL_PROVIDER_load(libctx, modulename);

    kemalgs =
        OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);
    if (kemalgs) {
        for (; kemalgs->algorithm_names != NULL; kemalgs++) {
            if (!is_kem_algorithm_hybrid(kemalgs->algorithm_names)) {
                continue;
            }
            if (test_oqs_kems_libctx(kemalgs->algorithm_names)) {
                fprintf(stderr, cGREEN "  KEM test succeeded: %s" cNORM "\n",
                        kemalgs->algorithm_names);
            } else {
                fprintf(stderr, cRED "  KEM test failed: %s" cNORM "\n",
                        kemalgs->algorithm_names);
                ERR_print_errors_fp(stderr);
                errcnt++;
            }
        }
    }

    sigalgs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_SIGNATURE,
                                            &query_nocache);
    if (sigalgs) {
        for (; sigalgs->algorithm_names != NULL; sigalgs++) {
            if (!is_signature_algorithm_hybrid(sigalgs->algorithm_names) &&
                !is_signature_algorithm_composite(sigalgs->algorithm_names)) {
                continue;
            }
            if (test_oqs_sigs_libctx(sigalgs->algorithm_names)) {
                fprintf(stderr,
                        cGREEN "  Signature test succeeded: %s" cNORM "\n",
                        sigalgs->algorithm_names);
            } else {
                fprintf(stderr, cRED "  Signature test failed: %s" cNORM "\n",
                        sigalgs->algorithm_names);
                ERR_print_errors_fp(stderr);
                errcnt++;
            }
        }
    }

    OSSL_PROVIDER_unload(oqsprov);
    OSSL_LIB_CTX_free(libctx);

    TEST_ASSERT(errcnt == 0)
    return !test;
}
