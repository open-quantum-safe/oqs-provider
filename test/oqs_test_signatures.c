// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/evp.h>
#include <openssl/provider.h>
#include "test_common.h"

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *certsdir = NULL;
static char *srpvfile = NULL;
static char *tmpfilename = NULL;

static const char *sigalg_names[] = {
///// OQS_TEMPLATE_FRAGMENT_SIGNATURE_CASES_START
  "oqs_sig_default",
  "dilithium2",
  "dilithium3",
  "dilithium5",
  "dilithium2_aes",
  "dilithium3_aes",
  "dilithium5_aes",
  "falcon512",
  "falcon1024",
  "picnicl1full",
  "picnic3l1",
  "rainbowIclassic",
  "rainbowVclassic",
  "sphincsharaka128frobust",
  "sphincssha256128frobust",
  "sphincsshake256128frobust",
///// OQS_TEMPLATE_FRAGMENT_SIGNATURE_CASES_END
};

static int test_oqs_signatures(const char *sigalg_name)
{
  EVP_MD_CTX *mdctx = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  const char msg[] = "The quick brown fox jumps over... you know what";
  unsigned char *sig;
  size_t siglen;

  int testresult =
    (mdctx = EVP_MD_CTX_new()) != NULL
    && (ctx = EVP_PKEY_CTX_new_from_name(libctx, sigalg_name, NULL)) != NULL
    && EVP_PKEY_keygen_init(ctx)
    && EVP_PKEY_gen(ctx, &key)
    && EVP_DigestSignInit_ex(mdctx, NULL, "SHA512", libctx, NULL, key)
    && EVP_DigestSignUpdate(mdctx, msg, sizeof(msg))
    && EVP_DigestSignFinal(mdctx, NULL, &siglen)
    && (sig = OPENSSL_malloc(siglen)) != NULL
    && EVP_DigestSignFinal(mdctx, sig, &siglen)
    && EVP_DigestVerifyInit_ex(mdctx, NULL, "SHA512", libctx, NULL, key)
    && EVP_DigestVerifyUpdate(mdctx, msg, sizeof(msg))
    && EVP_DigestVerifyFinal(mdctx, sig, siglen);

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(key);
  OPENSSL_free(ctx);
  return testresult;
}

#define nelem(a) (sizeof(a)/sizeof((a)[0]))

int main(int argc, char *argv[])
{
  size_t i;
  int errcnt = 0, test = 0;

  T((libctx = OSSL_LIB_CTX_new()) != NULL);
  T(argc == 3);
  modulename = argv[1];
  configfile = argv[2];

  T(OSSL_LIB_CTX_load_config(libctx, configfile));

  /* Check we have the expected providers available:
   * Note: default only needed if liboqs built using openssl,
   * so may be left away (in test/oqs.cnf if suitably build, see
   * https://github.com/open-quantum-safe/liboqs/wiki/Customizing-liboqs#OQS_USE_OPENSSL
   */
  T(OSSL_PROVIDER_available(libctx, modulename));
  T(OSSL_PROVIDER_available(libctx, "default"));

  for (i = 0; i < nelem(sigalg_names); i++) {
    if (test_oqs_signatures(sigalg_names[i])) {
      fprintf(stderr,
              cGREEN "  Signature test succeeded: %s" cNORM "\n",
              sigalg_names[i]);
    } else {
      fprintf(stderr,
              cRED "  Signature test failed: %s" cNORM "\n",
              sigalg_names[i]);
      ERR_print_errors_fp(stderr);
      errcnt++;
    }
  }

  OSSL_LIB_CTX_free(libctx);

  TEST_ASSERT(errcnt == 0)
  return !test;
}
