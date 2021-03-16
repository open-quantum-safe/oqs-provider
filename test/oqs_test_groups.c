// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <string.h>
#include "ssltestlib.h"
#include "test_common.h"

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *certsdir = NULL;
static char *srpvfile = NULL;

char *test_mk_file_path(const char *dir, const char *file)
{
# ifndef OPENSSL_SYS_VMS
    const char *sep = "/";
# else
    const char *sep = "";
# endif
    size_t len = strlen(dir) + strlen(sep) + strlen(file) + 1;
    char *full_file = OPENSSL_zalloc(len);

    if (full_file != NULL) {
        OPENSSL_strlcpy(full_file, dir, len);
        OPENSSL_strlcat(full_file, sep, len);
        OPENSSL_strlcat(full_file, file, len);
    }

    return full_file;
}


static const char *group_names[] = {
///// OQS_TEMPLATE_FRAGMENT_GROUP_CASES_START
  "frodo640aes",
  "frodo640shake",
  "frodo976aes",
  "frodo976shake",
  "frodo1344aes",
  "frodo1344shake",
  "bike1l1cpa",
  "bike1l3cpa",
  "kyber512",
  "kyber768",
  "kyber1024",
  "ntru_hps2048509",
  "ntru_hps2048677",
  "ntru_hps4096821",
  "ntru_hrss701",
  "lightsaber",
  "saber",
  "firesaber",
  "sidhp434",
  "sidhp503",
  "sidhp610",
  "sidhp751",
  "sikep434",
  "sikep503",
  "sikep610",
  "sikep751",
  "bike1l1fo",
  "bike1l3fo",
  "kyber90s512",
  "kyber90s768",
  "kyber90s1024",
  "hqc128",
  "hqc192",
  "hqc256",
  "ntrulpr653",
  "ntrulpr761",
  "ntrulpr857",
  "sntrup653",
  "sntrup761",
  "sntrup857",
///// OQS_TEMPLATE_FRAGMENT_GROUP_CASES_END
  "p256_sikep434"
};

static int test_oqs_groups(const char *group_name)
{
  SSL_CTX *cctx = NULL, *sctx = NULL;
  SSL *clientssl = NULL, *serverssl = NULL;
  int ret = 1, testresult = 0;

  testresult =
    create_ssl_ctx_pair(libctx, TLS_server_method(), TLS_client_method(),
                        TLS1_3_VERSION, TLS1_3_VERSION,
                        &sctx, &cctx, cert, privkey);
  if (!testresult) {
      ret = -1; goto err;
  }

  testresult =
    create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL);

  if (!testresult) {
      ret = -2; goto err;
  }

  testresult =
    SSL_set1_groups_list(serverssl, group_name);
  if (!testresult) {
      ret = -3; goto err;
  }

  testresult =
    SSL_set1_groups_list(clientssl, group_name);
  if (!testresult) {
      ret = -4; goto err;
  }

  testresult =
    create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE);
  if (!testresult) {
      ret = -5; goto err;
  }

  err:
  SSL_free(serverssl);
  SSL_free(clientssl);
  SSL_CTX_free(sctx);
  SSL_CTX_free(cctx);

  return ret;
}

#define nelem(a) (sizeof(a)/sizeof((a)[0]))

int main(int argc, char *argv[])
{
  size_t i;
  int errcnt = 0, test = 0;

  T((libctx = OSSL_LIB_CTX_new()) != NULL);
  T(argc == 5);
  modulename = argv[1];
  configfile = argv[2];
  certsdir = argv[3];
  srpvfile = argv[4];

  T(cert = test_mk_file_path(certsdir, "servercert.pem"));
  T(privkey = test_mk_file_path(certsdir, "serverkey.pem"));

  T(OSSL_LIB_CTX_load_config(libctx, configfile));

  /* Check we have the expected providers available:
   * Note: default only needed if liboqs built using openssl,
   * so may be left away (in test/oqs.cnf if suitably build, see
   * https://github.com/open-quantum-safe/liboqs/wiki/Customizing-liboqs#OQS_USE_OPENSSL
   */
  T(OSSL_PROVIDER_available(libctx, modulename));
  T(OSSL_PROVIDER_available(libctx, "default"));

  for (i = 0; i < nelem(group_names); i++) {
    fprintf(stderr,
            cGREEN "  Testing...: %s" cNORM "\n",
            group_names[i]);
    int ret = test_oqs_groups(group_names[i]);
    if (ret >= 0) {
      fprintf(stderr,
              cGREEN "  KEM test succeeded: %s" cNORM "\n",
              group_names[i]);
    } else {
      fprintf(stderr,
              cRED "  KEM test failed: %s, return code: %d"  cNORM "\n",
              group_names[i], ret);
      ERR_print_errors_fp(stderr);
      errcnt++;
    }
  }

  OPENSSL_free(cert);
  OPENSSL_free(privkey);
  OSSL_LIB_CTX_free(libctx);
  TEST_ASSERT(errcnt == 0)
  return !test;
}
