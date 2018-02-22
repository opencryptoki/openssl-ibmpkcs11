/* hw_pkcs11.c (replace hw_trustway.c) */
/*
 * PKCS#11 engine for the OpenSSL project 2002
 * Developped by Bull Trustway R&D Networking & Security
 * Introduced and tested with Bull TrustWay CC2000 crypto hardware
 * Afchine.Madjlessi@bull.net Bull S.A. France
 * http://www.servers.bull.com/trustway
 *
 * ChangLog:
 *      * 6/30/2010 Updates to compile stand-alone and against openssl 1.0
 *      * 8/15/2005 Fixes suggested by opencryptoki-engines list
 *	* 1/1/2004 Modified to support digests, ciphers and openCryptoki
 *	  http://www.sf.net/projects/opencryptoki
 *	- Serge Hallyn <serue@us.ibm.com>
 *	- Kent Yoder <yoder1@us.ibm.com>
 *      - Peter Waltenberg <pwalten@au1.ibm.com>
 *	(C) International Business Machines Corporation 2004, 2005, 2010
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <unistd.h>

#include <openssl/e_os2.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>

#ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_PKCS11

#include "cryptoki.h"
#include "e_pkcs11_err.h"
#include "e_pkcs11.h"
/* SHA224, CAMELLIA */
#include "pkcs-11v2-20a3.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OLDER_OPENSSL
#endif

/* Constants used when creating the ENGINE */
static const char *engine_pkcs11_id = "ibmpkcs11";
static const char *engine_pkcs11_name = "PKCS#11 hardware engine support";

static int bind_pkcs11(ENGINE *e);

/* ENGINE level stuff */
static int pkcs11_init(ENGINE *e);
static int pkcs11_finish(ENGINE *e);
static int pkcs11_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)());
static int pkcs11_destroy(ENGINE *e);

#ifndef OPENSSL_NO_RSA
/* RSA stuff */
static int pkcs11_RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to,
		RSA *rsa, int padding);
static int pkcs11_RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
		RSA *rsa, int padding);
static int pkcs11_RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
		RSA *rsa, int padding);
static int pkcs11_RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
		RSA *rsa, int padding);
static int pkcs11_RSA_init(RSA *rsa);
static int pkcs11_RSA_finish(RSA *rsa);
static int pkcs11_RSA_generate_key(RSA *rsa, int bits, BIGNUM *bn_e, BN_GENCB *cb);

static EVP_PKEY *pkcs11_load_privkey(ENGINE*, const char* pubkey_file,
		UI_METHOD *ui_method, void *callback_data);
static EVP_PKEY *pkcs11_load_pubkey(ENGINE*, const char* pubkey_file,
		UI_METHOD *ui_method, void *callback_data);

CK_OBJECT_HANDLE pkcs11_FindOrCreateKey(CK_SESSION_HANDLE h, RSA* rsa, CK_OBJECT_CLASS oKey, CK_BBOOL fKeyCreate);
/* exported functions (not member of ENGINE inteface) */
RSA* pkcs11_RSA_generate_tmp_key(int bits,unsigned long e_value,void (*callback)(int,int,void *),void *cb_arg);
#endif

/* RAND stuff */
#ifdef OLDER_OPENSSL
static void pkcs11_rand_seed(const void *buf, int num);
static void pkcs11_rand_add(const void *buf, int num, double add_entropy);
#else
static int pkcs11_rand_seed(const void *buf, int num);
static int pkcs11_rand_add(const void *buf, int num, double add_entropy);
#endif
static void pkcs11_rand_cleanup(void);
static int pkcs11_rand_bytes(unsigned char *buf, int num);
static int pkcs11_rand_status(void);

/* cipher function prototypes */
static inline int pkcs11_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc, int alg);
static inline int pkcs11_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
		const unsigned char *in, size_t inlen);
static int pkcs11_cipher_cleanup(EVP_CIPHER_CTX *ctx);

static int pkcs11_des_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc);
static int pkcs11_tdes_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc);
static int pkcs11_aes_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc);
/* End cipher function prototypes */

/* Digest function prototypes */
static inline int pkcs11_digest_init(EVP_MD_CTX *ctx, int alg);
static int pkcs11_digest_update(EVP_MD_CTX *ctx, const void *in, size_t len);
static int pkcs11_digest_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in);
static int pkcs11_digest_finish(EVP_MD_CTX *ctx, unsigned char *md);
static inline int pkcs11_digest_cleanup(EVP_MD_CTX *ctx);

static inline int pkcs11_sha1_init(EVP_MD_CTX *ctx);
static inline int pkcs11_sha224_init(EVP_MD_CTX *ctx);
static inline int pkcs11_sha256_init(EVP_MD_CTX *ctx);
static inline int pkcs11_sha384_init(EVP_MD_CTX *ctx);
static inline int pkcs11_sha512_init(EVP_MD_CTX *ctx);
static inline int pkcs11_md5_init(EVP_MD_CTX *ctx);
static inline int pkcs11_ripemd160_init(EVP_MD_CTX *ctx);
/* End digest function prototypes */

static int pre_init_pkcs11(ENGINE *e);
static int pkcs11_engine_ciphers(ENGINE * e, const EVP_CIPHER ** cipher,
		const int **nids, int nid);
static int pkcs11_engine_digests(ENGINE * e, const EVP_MD ** digest,
		const int **nids, int nid);

/* The definitions for control commands specific to this engine */
#define PKCS11_CMD_SO_PATH		ENGINE_CMD_BASE
#define PKCS11_CMD_SLOT_ID		(ENGINE_CMD_BASE + 1)
static const ENGINE_CMD_DEFN pkcs11_cmd_defns[] =
{
	{ PKCS11_CMD_SO_PATH,
		"SO_PATH",
		"Specifies the path to the 'pkcs#11' shared library",
		ENGINE_CMD_FLAG_STRING
	},
	{ PKCS11_CMD_SLOT_ID,
		"SLOT_ID",
		"Specifies the slot containing the token to use",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{0, NULL, NULL, 0}
};

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_pkcs11(void)
{
   ENGINE *ret = ENGINE_new();
   if(!ret) {
      return NULL;
   }   
   if(!bind_helper(ret)) {
      ENGINE_free(ret);
      return NULL;
   }
   return ret;
}
                                                 
void ENGINE_load_pkcs11(void)
{
   ENGINE *toadd = engine_pkcs11();
   if(!toadd) return;
   ENGINE_add(toadd);
   ENGINE_free(toadd);
   ERR_clear_error();
}
#else
static int bind_helper(ENGINE *e, const char *id)
{
  if((NULL != id) && (strcmp(id, engine_pkcs11_id) != 0))
    return 0;
  return(bind_pkcs11(e));
}       
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif                                                                        
                                        
/*
 * Comments on approaches:
 *   At the moment, ciphers and digests are treated differently.
 *
 *   For ciphers, we use cipher_init to initialize the cryptoki
 *    cipher action, and update to encrypt.  There is no finalize
 *    or cleanup.
 *
 *   For digests, we use digest_init to initialize a context
 *    struct, digest_update to call C_DigestUpdate on the data that
 *    we are receiving, digest_finish to call C_DigestFinal(), and
 *    cleanup() to free the context struct.
 */

/* 
 * Each cipher action requires a new session.  We store the
 * session and its token in the context->cipher_data void* using
 * this struct
 */
struct token_session {
	struct _token *token;
	CK_SESSION_HANDLE session;
};

/*
 * For digests:
 * We call digest_init to start the context, digest_update
 * to start computing the digest on the data that is being
 * received and digest_finish to finish the digest operation.
 */
struct pkcs11_digest_ctx {
	int alg;
	int len;
	struct _token *token;
	CK_SESSION_HANDLE session;
};

/********/

#ifdef OLDER_OPENSSL
#define CIPHER_DATA(ctx) ((struct token_session *)(ctx->cipher_data))
#define MD_DATA(ctx) ((struct pkcs11_digest_ctx *)(ctx->md_data))
#else
#define CIPHER_DATA(ctx) ((struct token_session *)(EVP_CIPHER_CTX_get_cipher_data(ctx)))
#define MD_DATA(ctx) ((struct pkcs11_digest_ctx *)(EVP_MD_CTX_md_data(ctx)))
#endif

static int num_cipher_nids = 0;
static int num_digest_nids = 0;

#ifdef OLDER_OPENSSL
const EVP_CIPHER pkcs11_des_ecb = {
	NID_des_ecb,		/* NID */
	8,			/* Block size */
	8,			/* Key len */
	8,			/* IV len */
	EVP_CIPH_ECB_MODE,	/* flags */
	pkcs11_des_init_key,	/* init */
	pkcs11_cipher,	/* do_cipher */
	pkcs11_cipher_cleanup,	/* cleanup */
	sizeof(struct token_session),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,			/* misc ctrl ops */
	NULL			/* app data (ctx->cipher_data) */
};

const EVP_CIPHER pkcs11_des_cbc = {
	NID_des_cbc,		/* NID */
	8,			/* Block size */
	8,			/* Key len */
	8,			/* IV len */
	EVP_CIPH_CBC_MODE,	/* flags */
	pkcs11_des_init_key,	/* init */
	pkcs11_cipher,	/* do_cipher */
	pkcs11_cipher_cleanup,	/* cleanup */
	sizeof(struct token_session),	/* sizeof(ctx->cipher_data) */
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,			/* misc ctrl ops */
	NULL			/* app data (ctx->cipher_data) */
};
#else

#define DECLARE_DES_EVP(lmode, umode)					      \
static EVP_CIPHER *des_##lmode = NULL;					      \
static const EVP_CIPHER *pkcs11_des_##lmode(void)			      \
{									      \
	if (des_##lmode == NULL) {					      \
		EVP_CIPHER *cipher;					      \
		if (( cipher = EVP_CIPHER_meth_new(NID_des_##lmode,	      \
						   8, 8)) == NULL	      \
		|| !EVP_CIPHER_meth_set_iv_length(cipher, 8)		      \
		|| !EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_##umode##_MODE)\
		|| !EVP_CIPHER_meth_set_init(cipher, pkcs11_des_init_key)     \
		|| !EVP_CIPHER_meth_set_do_cipher(cipher, pkcs11_cipher)      \
		|| !EVP_CIPHER_meth_set_cleanup(cipher, pkcs11_cipher_cleanup)\
		|| !EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(	      \
							struct token_session))\
		|| !EVP_CIPHER_meth_set_set_asn1_params(cipher,		      \
						EVP_CIPHER_set_asn1_iv)       \
		|| !EVP_CIPHER_meth_set_get_asn1_params(cipher,		      \
						EVP_CIPHER_get_asn1_iv)) {    \
			EVP_CIPHER_meth_free(cipher);			      \
			cipher = NULL;					      \
		}							      \
		des_##lmode = cipher;					      \
	}								      \
	return des_##lmode;						      \
}									      \
									      \
static void pkcs11_des_##lmode##_destroy(void)				      \
{									      \
	EVP_CIPHER_meth_free(des_##lmode);				      \
	des_##lmode = NULL;						      \
}

DECLARE_DES_EVP(ecb, ECB)
DECLARE_DES_EVP(cbc, CBC)
#endif

#ifdef OLDER_OPENSSL
const EVP_CIPHER pkcs11_tdes_ecb = {
	NID_des_ede3_ecb,	/* NID */
	8,			/* Block size */
	24,			/* Key len */
	8,			/* IV len */
	EVP_CIPH_ECB_MODE,	/* flags */
	pkcs11_tdes_init_key,	/* init */
	pkcs11_cipher,	/* do_cipher */
	pkcs11_cipher_cleanup,	/* cleanup */
	sizeof(struct token_session),	/* sizeof(ctx->cipher_data) */
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,			/* misc ctrl ops */
	NULL			/* app data (ctx->cipher_data) */
};

const EVP_CIPHER pkcs11_tdes_cbc = {
	NID_des_ede3_cbc,	/* NID */
	8,			/* Block size */
	24,			/* Key len */
	8,			/* IV len */
	EVP_CIPH_CBC_MODE,	/* flags */
	pkcs11_tdes_init_key,	/* init */
	pkcs11_cipher,	/* do_cipher */
	pkcs11_cipher_cleanup,	/* cleanup */
	sizeof(struct token_session),	/* sizeof(ctx->cipher_data) */
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,			/* misc ctrl ops */
	NULL			/* app data (ctx->cipher_data) */
};
#else

#define DECLARE_TDES_EVP(lmode, umode)					      \
static EVP_CIPHER *tdes_##lmode = NULL;					      \
static const EVP_CIPHER *pkcs11_tdes_##lmode(void)			      \
{									      \
	if (tdes_##lmode == NULL) {					      \
		EVP_CIPHER *cipher;					      \
		if (( cipher = EVP_CIPHER_meth_new(NID_des_ede3_##lmode,      \
						   8, 24)) == NULL	      \
		|| !EVP_CIPHER_meth_set_iv_length(cipher, 8)		      \
		|| !EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_##umode##_MODE)\
		|| !EVP_CIPHER_meth_set_init(cipher, pkcs11_tdes_init_key)    \
		|| !EVP_CIPHER_meth_set_do_cipher(cipher, pkcs11_cipher)      \
		|| !EVP_CIPHER_meth_set_cleanup(cipher, pkcs11_cipher_cleanup)\
		|| !EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(	      \
							struct token_session))\
		|| !EVP_CIPHER_meth_set_set_asn1_params(cipher,		      \
						EVP_CIPHER_set_asn1_iv)       \
		|| !EVP_CIPHER_meth_set_get_asn1_params(cipher,		      \
						EVP_CIPHER_get_asn1_iv)) {    \
			EVP_CIPHER_meth_free(cipher);			      \
			cipher = NULL;					      \
		}							      \
		tdes_##lmode = cipher;					      \
	}								      \
	return tdes_##lmode;						      \
}									      \
									      \
static void pkcs11_tdes_##lmode##_destroy(void)				      \
{									      \
	EVP_CIPHER_meth_free(tdes_##lmode);				      \
	tdes_##lmode = NULL;						      \
}

DECLARE_TDES_EVP(ecb, ECB)
DECLARE_TDES_EVP(cbc, CBC)
#endif

#ifdef OLDER_OPENSSL
/* AES ECB */
const EVP_CIPHER pkcs11_aes_128_ecb = {
	NID_aes_128_cbc,	/* NID */
	16,			/* Block size */
	16,			/* Key len */
	16,			/* IV len */
	EVP_CIPH_ECB_MODE,	/* flags */
	pkcs11_aes_init_key,	/* init */
	pkcs11_cipher,	/* do_cipher */
	pkcs11_cipher_cleanup,	/* cleanup */
	sizeof(struct token_session),	/* sizeof(ctx->cipher_data) */
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,			/* misc ctrl ops */
	NULL			/* app data (ctx->cipher_data) */
};

const EVP_CIPHER pkcs11_aes_192_ecb = {
	NID_aes_192_ecb,	/* NID */
	16,			/* Block size */
	24,			/* Key len */
	16,			/* IV len */
	EVP_CIPH_ECB_MODE,	/* flags */
	pkcs11_aes_init_key,	/* init */
	pkcs11_cipher,	/* do_cipher */
	pkcs11_cipher_cleanup,	/* cleanup */
	sizeof(struct token_session),	/* sizeof(ctx->cipher_data) */
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,			/* misc ctrl ops */
	NULL			/* app data (ctx->cipher_data) */
};

const EVP_CIPHER pkcs11_aes_256_ecb = {
	NID_aes_256_ecb,	/* NID */
	16,			/* Block size */
	32,			/* Key len */
	16,			/* IV len */
	EVP_CIPH_ECB_MODE,	/* flags */
	pkcs11_aes_init_key,	/* init */
	pkcs11_cipher,	/* do_cipher */
	pkcs11_cipher_cleanup,	/* cleanup */
	sizeof(struct token_session),	/* sizeof(ctx->cipher_data) */
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,			/* misc ctrl ops */
	NULL			/* app data (ctx->cipher_data) */
};

/* AES CBC */
const EVP_CIPHER pkcs11_aes_128_cbc = {
	NID_aes_128_cbc,	/* NID */
	16,			/* Block size */
	16,			/* Key len */
	16,			/* IV len */
	EVP_CIPH_CBC_MODE,	/* flags */
	pkcs11_aes_init_key,	/* init */
	pkcs11_cipher,	/* do_cipher */
	pkcs11_cipher_cleanup,	/* cleanup */
	sizeof(struct token_session),	/* sizeof(ctx->cipher_data) */
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,			/* misc ctrl ops */
	NULL			/* app data (ctx->cipher_data) */
};

const EVP_CIPHER pkcs11_aes_192_cbc = {
	NID_aes_192_cbc,	/* NID */
	16,			/* Block size */
	24,			/* Key len */
	16,			/* IV len */
	EVP_CIPH_CBC_MODE,	/* flags */
	pkcs11_aes_init_key,	/* init */
	pkcs11_cipher,	/* do_cipher */
	pkcs11_cipher_cleanup,	/* cleanup */
	sizeof(struct token_session),	/* sizeof(ctx->cipher_data) */
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,			/* misc ctrl ops */
	NULL			/* app data (ctx->cipher_data) */
};

const EVP_CIPHER pkcs11_aes_256_cbc = {
	NID_aes_256_cbc,	/* NID */
	16,			/* Block size */
	32,			/* Key len */
	16,			/* IV len */
	EVP_CIPH_CBC_MODE,	/* flags */
	pkcs11_aes_init_key,	/* init */
	pkcs11_cipher,	/* do_cipher */
	pkcs11_cipher_cleanup,	/* cleanup */
	sizeof(struct token_session),	/* sizeof(ctx->cipher_data) */
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,			/* misc ctrl ops */
	NULL			/* app data (ctx->cipher_data) */
};
#else

#define EVP_CIPHER_keylen_AES_128 16
#define EVP_CIPHER_keylen_AES_192 24
#define EVP_CIPHER_keylen_AES_256 32

#define DECLARE_AES_EVP(ksize, lmode, umode)				      \
static EVP_CIPHER *aes_##ksize##_##lmode = NULL;			      \
static const EVP_CIPHER *pkcs11_aes_##ksize##_##lmode(void)		      \
{									      \
	if (aes_##ksize##_##lmode == NULL) {				      \
		EVP_CIPHER *cipher;					      \
		if (( cipher = EVP_CIPHER_meth_new(NID_aes_##ksize##_##lmode, \
				    8,					      \
				    EVP_CIPHER_keylen_AES_##ksize)) == NULL   \
		|| !EVP_CIPHER_meth_set_iv_length(cipher, 16)		      \
		|| !EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_##umode##_MODE)\
		|| !EVP_CIPHER_meth_set_init(cipher, pkcs11_aes_init_key)     \
		|| !EVP_CIPHER_meth_set_do_cipher(cipher, pkcs11_cipher)      \
		|| !EVP_CIPHER_meth_set_cleanup(cipher, pkcs11_cipher_cleanup)\
		|| !EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(	      \
							struct token_session))\
		|| !EVP_CIPHER_meth_set_set_asn1_params(cipher,		      \
						EVP_CIPHER_set_asn1_iv)       \
		|| !EVP_CIPHER_meth_set_get_asn1_params(cipher,		      \
						EVP_CIPHER_get_asn1_iv)) {    \
			EVP_CIPHER_meth_free(cipher);			      \
			cipher = NULL;					      \
		}							      \
		aes_##ksize##_##lmode = cipher;				      \
	}								      \
	return aes_##ksize##_##lmode;					      \
}									      \
									      \
static void pkcs11_aes_##ksize##_##lmode##_destroy(void)		      \
{									      \
	EVP_CIPHER_meth_free(aes_##ksize##_##lmode);			      \
	aes_##ksize##_##lmode = NULL;					      \
}

DECLARE_AES_EVP(128, cbc, CBC)
DECLARE_AES_EVP(192, cbc, CBC)
DECLARE_AES_EVP(256, cbc, CBC)
DECLARE_AES_EVP(128, ecb, ECB)
DECLARE_AES_EVP(192, ecb, ECB)
DECLARE_AES_EVP(256, ecb, ECB)
#endif

#ifdef OLDER_OPENSSL
/* Message Digests */
const EVP_MD pkcs11_sha1 = {
       NID_sha1,
       NID_sha1WithRSAEncryption,
       SHA_DIGEST_LENGTH,
       EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
       pkcs11_sha1_init,
       pkcs11_digest_update,
       pkcs11_digest_finish, /* final */
       pkcs11_digest_copy,
       pkcs11_digest_cleanup, /* cleanup */
       EVP_PKEY_RSA_method,
       SHA_CBLOCK,
       sizeof(struct pkcs11_digest_ctx)
};

const EVP_MD pkcs11_sha224 = {
       NID_sha224,
       NID_sha224WithRSAEncryption,
       SHA224_DIGEST_LENGTH,
       EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
       pkcs11_sha224_init,
       pkcs11_digest_update,
       pkcs11_digest_finish, /* final */
       pkcs11_digest_copy,
       pkcs11_digest_cleanup, /* cleanup */
       EVP_PKEY_RSA_method,
       SHA256_CBLOCK,
       sizeof(struct pkcs11_digest_ctx)
};

const EVP_MD pkcs11_sha256 = {
       NID_sha256,
       NID_sha256WithRSAEncryption,
       SHA256_DIGEST_LENGTH,
       EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
       pkcs11_sha256_init,
       pkcs11_digest_update,
       pkcs11_digest_finish, /* final */
       pkcs11_digest_copy,
       pkcs11_digest_cleanup, /* cleanup */
       EVP_PKEY_RSA_method,
       SHA256_CBLOCK,
       sizeof(struct pkcs11_digest_ctx)
};

const EVP_MD pkcs11_sha384 = {
       NID_sha384,
       NID_sha384WithRSAEncryption,
       SHA384_DIGEST_LENGTH,
       EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
       pkcs11_sha384_init,
       pkcs11_digest_update,
       pkcs11_digest_finish, /* final */
       pkcs11_digest_copy,
       pkcs11_digest_cleanup, /* cleanup */
       EVP_PKEY_RSA_method,
       SHA512_CBLOCK,
       sizeof(struct pkcs11_digest_ctx)
};

const EVP_MD pkcs11_sha512 = {
       NID_sha512,
       NID_sha512WithRSAEncryption,
       SHA512_DIGEST_LENGTH,
       EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
       pkcs11_sha512_init,
       pkcs11_digest_update,
       pkcs11_digest_finish, /* final */
       pkcs11_digest_copy,
       pkcs11_digest_cleanup, /* cleanup */
       EVP_PKEY_RSA_method,
       SHA512_CBLOCK,
       sizeof(struct pkcs11_digest_ctx)
};

const EVP_MD pkcs11_md5 = {
       NID_md5,
       NID_md5WithRSAEncryption,
       MD5_DIGEST_LENGTH,
       0,
       pkcs11_md5_init,
       pkcs11_digest_update,
       pkcs11_digest_finish, /* final */
       pkcs11_digest_copy,
       pkcs11_digest_cleanup,  /* cleanup */
       EVP_PKEY_RSA_method,
       MD5_CBLOCK,
       sizeof(struct pkcs11_digest_ctx)
};

const EVP_MD pkcs11_ripemd160 = {
       NID_ripemd160,
       NID_ripemd160WithRSA,
       RIPEMD160_DIGEST_LENGTH,
       0, /* flags */
       pkcs11_ripemd160_init,
       pkcs11_digest_update,
       pkcs11_digest_finish,  /* final */
       pkcs11_digest_copy,
       pkcs11_digest_cleanup,  /* cleanup */
       EVP_PKEY_RSA_method,
       RIPEMD160_CBLOCK,
       sizeof(struct pkcs11_digest_ctx)
};
#else

#define DECLARE_DIGEST_EVP(dig, len, enc)				      \
static EVP_MD *dig##_md = NULL;						      \
static const EVP_MD *pkcs11_##dig(void)					      \
{									      \
	if (dig##_md == NULL) {						      \
		EVP_MD *md;						      \
		if (( md = EVP_MD_meth_new(NID_##dig,			      \
					NID_##dig##WithRSA##enc)) == NULL     \
		   || !EVP_MD_meth_set_result_size(md, len##_DIGEST_LENGTH)   \
		   || !EVP_MD_meth_set_input_blocksize(md, len##_CBLOCK)      \
		   || !EVP_MD_meth_set_app_datasize(md, 		      \
					sizeof(struct pkcs11_digest_ctx))     \
		   || !EVP_MD_meth_set_flags(md, 0)			      \
		   || !EVP_MD_meth_set_init(md, pkcs11_##dig##_init)	      \
		   || !EVP_MD_meth_set_update(md, pkcs11_digest_update)	      \
		   || !EVP_MD_meth_set_final(md, pkcs11_digest_finish)	      \
		   || !EVP_MD_meth_set_copy(md, pkcs11_digest_copy)	      \
		   || !EVP_MD_meth_set_cleanup(md, pkcs11_digest_cleanup)) {  \
			EVP_MD_meth_free(md);				      \
			md = NULL;					      \
		}							      \
		dig##_md = md;						      \
	}								      \
	return dig##_md;						      \
}									      \
									      \
static void pkcs11_##dig##_destroy(void)				      \
{									      \
	EVP_MD_meth_free(dig##_md);					      \
	dig##_md = NULL;						      \
}

DECLARE_DIGEST_EVP(sha1, SHA, Encryption)
DECLARE_DIGEST_EVP(sha224, SHA256, Encryption)
DECLARE_DIGEST_EVP(sha256, SHA256, Encryption)
DECLARE_DIGEST_EVP(sha384, SHA512, Encryption)
DECLARE_DIGEST_EVP(sha512, SHA512, Encryption)
DECLARE_DIGEST_EVP(md5, MD5, Encryption)
DECLARE_DIGEST_EVP(ripemd160, RIPEMD160,)
#endif

/********/
#ifndef OPENSSL_NO_RSA
#ifdef OLDER_OPENSSL
static RSA_METHOD pkcs11_rsa =
{
	"PKCS#11 RSA",
	pkcs11_RSA_public_encrypt,                     /* rsa_pub_encrypt */
	pkcs11_RSA_public_decrypt,                     /* rsa_pub_decrypt */
	pkcs11_RSA_private_encrypt,                    /* rsa_priv_encrypt */
	pkcs11_RSA_private_decrypt,                    /* rsa_priv_decrypt */
	NULL,                                          /* rsa_mod_exp */   
	NULL,                                          /* bn_mod_exp */
	pkcs11_RSA_init,                               /* init */
	pkcs11_RSA_finish,                             /* finish */
	RSA_FLAG_SIGN_VER,                             /* flags */
	NULL,                                          /* app_data */
	NULL,                                          /* rsa_sign */
	NULL,                                          /* rsa_verify */
	pkcs11_RSA_generate_key                       /* rsa_generate_key */ 
};
#else
static RSA_METHOD *pkcs11_rsa = NULL;
#endif

/*RSA_METHOD *PKCS11_RSA(void)
{
	return(&pkcs11_rsa);
}*/
#endif

extern const char *RAND_version;

static RAND_METHOD pkcs11_random =
{
	/* "PKCS11 RAND method", */
	pkcs11_rand_seed,
	pkcs11_rand_bytes,
	pkcs11_rand_cleanup,
	pkcs11_rand_add,
	pkcs11_rand_bytes,
	pkcs11_rand_status
};


RAND_METHOD *PKCS11_RAND(void)
{
	return(&pkcs11_random);
}

static CK_FUNCTION_LIST_PTR pFunctionList = NULL;

/* These are the static string constants for the DSO file name and the function
 * symbol names to bind to. 
 */
static unsigned char PKCS11_KEY_ID[] = "OpenSSL PKCS#11";

/* String used to detect a CC2000 Bull TrustWay crypto card */
#define BULL_TRUSTWAY_LIBRARY_DESCRIPTION "Bull CC2000 PKCS#11 Library     "
static CK_BBOOL Bull_TrustWay = FALSE;
#undef BULL_CC2000 /* use Bull CC2000 hardware crypto */

#undef BULL_CRYPTOBOX /* use Bull CryptoBox remote hardware crypto */

#undef GPKCS11 /* use GPKCS11  software crypto */

#if defined(BULL_CC2000)
static const char def_PKCS11_LIBNAME[] = "gpkcs11cc2000";
#elif defined(BULL_CRYPTOBOX)
static const char def_PKCS11_LIBNAME[] = "cryptobox_clnt";
extern CK_RV C_InitializeRpc (CK_CHAR_PTR, CK_CHAR_PTR, CK_ULONG_PTR);
#elif defined(GPKCS11) 
static const char def_PKCS11_LIBNAME[] = "gpkcs11";
#elif defined(OPENCRYPTOKI)
static char *def_PKCS11_LIBNAME = "libopencryptoki.so";
#else
static const char def_PKCS11_LIBNAME[] = "pkcs11";
#endif
static const char PKCS11_GET_FUNCTION_LIST[] = "C_GetFunctionList";

/* Size of an SSL signature: MD5+SHA1. up to allow SHA512  */
//#define SSL_SIG_LENGTH	64
#define SSL_SIG_LENGTH	36
#define KEY_STORE 1
static CK_BBOOL true = TRUE;
static CK_BBOOL false = FALSE;
static CK_SLOT_ID SLOTID = 0XFFFFFFFF;

#ifndef OPENSSL_NO_RSA
/* Where in the CRYPTO_EX_DATA stack we stick our per-key contexts */
static int rsaPubKey = -1;
static int rsaPrivKey = -1;
static int deletePubKeyOnFree = -1;
static int deletePrivKeyOnFree = -1;
static int pkcs11Session = -1;
#endif

static int PKCS11_Initialized = 0;

#ifdef PKCS11_DEBUG
#define DBG_fprintf(args...) do { fprintf(stderr, args); fflush(stderr); } while (0)
#else
#define DBG_fprintf(args...)
#endif

void pkcs11_atfork_init(void)
{
	DBG_fprintf("pkcs11_atfork_init: called (pid %d)\n", getpid());
	PKCS11_Initialized = 0;
}

#define pkcs11_die(func, reason, rv) \
{ \
	char tmpbuf[20]; \
	PKCS11err(func, reason); \
	sprintf(tmpbuf, "%lx", rv); \
	ERR_add_error_data(2, "PKCS11 CK_RV=0X", tmpbuf); \
}

struct token_session *pkcs11_getSession(void)
{
	CK_RV rv;
	struct token_session *wrapper;

	if (!pkcs11_token) {
		PKCS11err(PKCS11_F_GETSESSION, PKCS11_R_NO_SLOT_SELECTED);
		return NULL;
	}

	wrapper = OPENSSL_malloc(sizeof (struct token_session));
	if (!wrapper) {
		PKCS11err(PKCS11_F_GETSESSION, PKCS11_R_MALLOC_FAILURE);
		return NULL;
	}
	wrapper->token = pkcs11_token;

	if (!PKCS11_Initialized) {
		rv = pFunctionList->C_Initialize(NULL);
		if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			pkcs11_die(PKCS11_F_GETSESSION, PKCS11_R_INITIALIZE, rv);
			return NULL;
		}
		PKCS11_Initialized = 1;
	}

	rv = pFunctionList->C_OpenSession(wrapper->token->slot_id,
			CKF_SERIAL_SESSION | CKF_RW_SESSION,
			NULL_PTR,
			NULL_PTR,
			&wrapper->session);
	if (rv != CKR_OK) {
		pkcs11_die(PKCS11_F_GETSESSION, PKCS11_R_OPENSESSION, rv);
		return NULL;
	}

	return wrapper;
}

char *alg_to_string(int alg_type)
{
	switch (alg_type) {
		case alg_des:
			return "des";
		case alg_tdes:
			return "tdes";
		case alg_aes:
			return "aes";
		case alg_rsa:
			return "rsa";
		case alg_sha:
			return "sha";
		case alg_md5:
			return "md5";
		case alg_ripemd:
			return "ripemd";
		default:
			return "invalid algorithm";
	}
}

/* This internal function is used by ENGINE_pkcs11() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_pkcs11(ENGINE *e)
{
	DBG_fprintf("%s\n", __FUNCTION__);

	if (!ENGINE_set_id(e, engine_pkcs11_id) ||
	    !ENGINE_set_name(e, engine_pkcs11_name) ||
	    !ENGINE_set_RAND(e, &pkcs11_random) ||
	    !ENGINE_set_init_function(e, pkcs11_init) ||
	    !ENGINE_set_ciphers(e, pkcs11_engine_ciphers) ||
	    !ENGINE_set_digests(e, pkcs11_engine_digests) ||
	    !ENGINE_set_destroy_function(e, pkcs11_destroy) ||
	    !ENGINE_set_finish_function(e, pkcs11_finish) ||
	    !ENGINE_set_ctrl_function(e, pkcs11_ctrl) ||
	    !ENGINE_set_cmd_defns(e, pkcs11_cmd_defns))
		return 0;

	/* Ensure the pkcs11 error handling is set up */
	ERR_load_pkcs11_strings();

	pre_init_pkcs11(e);

	return 1;
}

#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_helper(ENGINE *e, const char *id)
{
	DBG_fprintf("%s\n", __FUNCTION__);

	if(id && (strcmp(id, engine_pkcs11_id) != 0))
		return 0;
	if(!bind_pkcs11(e))
		return 0;
	return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#else
static ENGINE *engine_pkcs11(void)
{
	DBG_fprintf("%s\n", __FUNCTION__);

	ENGINE *ret = ENGINE_new();
	if(!ret)
		return NULL;
	if(!bind_pkcs11(ret))
	{
		ENGINE_free(ret);
		return NULL;
	}

	pre_init_pkcs11(ret);

	return ret;
}

void ENGINE_load_pkcs11(void)
{
	DBG_fprintf("%s\n", __FUNCTION__);

	ENGINE *e_pkcs11 = engine_pkcs11();
	if(!e_pkcs11) return;
	ENGINE_add(e_pkcs11);
	ENGINE_free(e_pkcs11);
	ERR_clear_error();
}
#endif

#define PKCS11_MAX_ALGS 20

static int
get_pkcs11_ciphers(const int **retnids)
{
	static int nids[PKCS11_MAX_ALGS];
	int i, count = 0, *pkcs11_implemented_ciphers;

	if (pkcs11_token)
		pkcs11_implemented_ciphers = pkcs11_token->pkcs11_implemented_ciphers;
	else {
		PKCS11err(PKCS11_F_GET_PKCS11_CIPHERS, PKCS11_R_NO_SLOT_SELECTED);
		return 0;
	}

	memset(nids, 0, sizeof(nids));
	*retnids = NULL;

	for (i=0; i<NUM_NID; i++) {
		if (pkcs11_implemented_ciphers[i])
			nids[count++] = i;
	}

	if (count)
		*retnids = nids;
	return count;
}

static int
get_pkcs11_digests(const int **retnids)
{
	static int nids[PKCS11_MAX_ALGS];
	int i, count = 0, *pkcs11_implemented_digests;

	if (pkcs11_token)
		pkcs11_implemented_digests = pkcs11_token->pkcs11_implemented_digests;
	else {
		PKCS11err(PKCS11_F_GET_PKCS11_DIGESTS, PKCS11_R_NO_SLOT_SELECTED);
		return 0;
	}

	memset(nids, 0, sizeof(nids));
	*retnids = NULL;

	for (i=0; i<NUM_NID; i++) {
		if (pkcs11_implemented_digests[i])
			nids[count++] = i;
	}

	if (count)
		*retnids = nids;
	return count;
}

/*
 * ENGINE calls this to find out how to deal with
 * a particular NID in the ENGINE.
 */
static int pkcs11_engine_ciphers(ENGINE * e, const EVP_CIPHER ** cipher,
		const int **nids, int nid)
{
	if (!cipher)
		return get_pkcs11_ciphers(nids);

	if (!pkcs11_token) {
		PKCS11err(PKCS11_F_ENGINE_CIPHERS, PKCS11_R_NO_SLOT_SELECTED);
		return 0;
	}

	/* If the algorithm requested was not added to the list at
	 * engine init time, don't return a reference to that structure.
	 */
	if (pkcs11_token->pkcs11_implemented_ciphers[nid]) {
		switch (nid) {
			case NID_aes_128_ecb:
#ifdef OLDER_OPENSSL
				*cipher = &pkcs11_aes_128_ecb;
#else
				*cipher = pkcs11_aes_128_ecb();
#endif
				break;
			case NID_aes_192_ecb:
#ifdef OLDER_OPENSSL
				*cipher = &pkcs11_aes_192_ecb;
#else
				*cipher = pkcs11_aes_192_ecb();
#endif
				break;
			case NID_aes_256_ecb:
#ifdef OLDER_OPENSSL
				*cipher = &pkcs11_aes_256_ecb;
#else
				*cipher = pkcs11_aes_256_ecb();
#endif
				break;
			case NID_aes_128_cbc:
#ifdef OLDER_OPENSSL
				*cipher = &pkcs11_aes_128_cbc;
#else
				*cipher = pkcs11_aes_128_cbc();
#endif
				break;
			case NID_aes_192_cbc:
#ifdef OLDER_OPENSSL
				*cipher = &pkcs11_aes_192_cbc;
#else
				*cipher = pkcs11_aes_192_cbc();
#endif
				break;
			case NID_aes_256_cbc:
#ifdef OLDER_OPENSSL
				*cipher = &pkcs11_aes_256_cbc;
#else
				*cipher = pkcs11_aes_256_cbc();
#endif
				break;
			case NID_des_ecb:
#ifdef OLDER_OPENSSL
				*cipher = &pkcs11_des_ecb;
#else
				*cipher = pkcs11_des_ecb();
#endif
				break;
			case NID_des_cbc:
#ifdef OLDER_OPENSSL
				*cipher = &pkcs11_des_cbc;
#else
				*cipher = pkcs11_des_cbc();
#endif
				break;
			case NID_des_ede3_ecb:
#ifdef OLDER_OPENSSL
				*cipher = &pkcs11_tdes_ecb;
#else
				*cipher = pkcs11_tdes_ecb();
#endif
				break;
			case NID_des_ede3_cbc:
#ifdef OLDER_OPENSSL
				*cipher = &pkcs11_tdes_cbc;
#else
				*cipher = pkcs11_tdes_cbc();
#endif
				break;
			default:
				*cipher = NULL;
				break;
		}
	}
	return (*cipher != NULL);
}

static int pkcs11_engine_digests(ENGINE * e, const EVP_MD ** digest,
		const int **nids, int nid)
{
	if (!digest)
		return get_pkcs11_digests(nids);

	if (!pkcs11_token) {
		PKCS11err(PKCS11_F_ENGINE_DIGESTS, PKCS11_R_NO_SLOT_SELECTED);
		return 0;
	}

	if (pkcs11_token->pkcs11_implemented_digests[nid]) {
		switch (nid) {
			case NID_ripemd160:
#ifdef OLDER_OPENSSL
				*digest = &pkcs11_ripemd160;
#else
				*digest = pkcs11_ripemd160();
#endif
				break;
			case NID_md5:
#ifdef OLDER_OPENSSL
				*digest = &pkcs11_md5;
#else
				*digest = pkcs11_md5();
#endif
				break;
			case NID_sha1:
#ifdef OLDER_OPENSSL
				*digest = &pkcs11_sha1;
#else
				*digest = pkcs11_sha1();
#endif
				break;
			case NID_sha224:
#ifdef OLDER_OPENSSL
				*digest = &pkcs11_sha224;
#else
				*digest = pkcs11_sha224();
#endif
				break;
			case NID_sha256:
#ifdef OLDER_OPENSSL
				*digest = &pkcs11_sha256;
#else
				*digest = pkcs11_sha256();
#endif
				break;
			case NID_sha384:
#ifdef OLDER_OPENSSL
				*digest = &pkcs11_sha384;
#else
				*digest = pkcs11_sha384();
#endif
				break;
			case NID_sha512:
#ifdef OLDER_OPENSSL
				*digest = &pkcs11_sha512;
#else
				*digest = pkcs11_sha512();
#endif
				break;
			default:
				*digest = NULL;
				break;
		}
	}
	return (*digest != NULL);
}

void *pkcs11_dso = NULL;

/* These are the static string constants for the DSO file name and the function
 * symbol names to bind to. 
 */
static const char *PKCS11_LIBNAME = NULL;
static const char *get_PKCS11_LIBNAME(void)
{
	if(PKCS11_LIBNAME)
		return PKCS11_LIBNAME;
	return def_PKCS11_LIBNAME;
}
static void free_PKCS11_LIBNAME(void)
{
	if(PKCS11_LIBNAME)
		OPENSSL_free((void*)PKCS11_LIBNAME);
	PKCS11_LIBNAME = NULL;
}
static long set_PKCS11_LIBNAME(const char *name)
{
	free_PKCS11_LIBNAME();
	return ((PKCS11_LIBNAME = BUF_strdup(name)) != NULL ? 1 : 0);
}

/* Add new NID's based on this slot's token */
void pkcs11_regToken(ENGINE *e, struct _token *tok)
{
	CK_RV rv;
	CK_ULONG mech_cnt;
	CK_MECHANISM_TYPE_PTR mech_list;
	int i;

	DBG_fprintf("%s\n", __FUNCTION__);

	if (!tok)
		return;

	rv = pFunctionList->C_GetMechanismList(tok->slot_id, NULL_PTR, &mech_cnt);
	if (rv != CKR_OK) {
		pkcs11_die(PKCS11_F_ADDTOKEN, PKCS11_R_GETMECHANISMLIST, rv);
		goto err;
	}

	/* Bounds check mech_cnt ? */
	mech_list = (CK_MECHANISM_TYPE_PTR) OPENSSL_malloc(mech_cnt * sizeof(CK_MECHANISM_TYPE));
	if (mech_list == NULL) {
		pkcs11_die(PKCS11_F_ADDTOKEN, PKCS11_R_MALLOC_FAILURE, rv);
		goto err;
	}

	rv = pFunctionList->C_GetMechanismList(tok->slot_id, mech_list, &mech_cnt);
	if (rv != CKR_OK) {
		pkcs11_die(PKCS11_F_ADDTOKEN, PKCS11_R_GETMECHANISMLIST, rv);
		goto err_free;
	}

	/* Check which mechanisms are performed in hardware */
	for( i = 0; i < mech_cnt; i++ ) {
		switch (mech_list[i]) {
			case CKM_RSA_PKCS_KEY_PAIR_GEN:
			case CKM_RSA_PKCS:
			case CKM_RSA_9796:
			case CKM_RSA_X_509:
			case CKM_RSA_PKCS_OAEP:
			case CKM_RSA_X9_31:
			case CKM_RSA_X9_31_KEY_PAIR_GEN:
			case CKM_MD5_RSA_PKCS:
#ifndef OPENSSL_NO_RSA
				DBG_fprintf("%s: registering RSA\n", __FUNCTION__);
#ifdef OLDER_OPENSSL
				ENGINE_set_RSA(e, &pkcs11_rsa);
#else
				ENGINE_set_RSA(e, pkcs11_rsa);
				pkcs11_rsa = RSA_meth_new("PKCS#11 RSA", 0);
				RSA_meth_set_pub_enc(pkcs11_rsa,
						pkcs11_RSA_public_encrypt);
				RSA_meth_set_pub_dec(pkcs11_rsa,
						pkcs11_RSA_public_decrypt);
				RSA_meth_set_priv_enc(pkcs11_rsa,
						pkcs11_RSA_private_encrypt);
				RSA_meth_set_priv_dec(pkcs11_rsa,
						pkcs11_RSA_private_decrypt);
				RSA_meth_set_init(pkcs11_rsa,
						pkcs11_RSA_init);
				RSA_meth_set_finish(pkcs11_rsa,
						pkcs11_RSA_finish);
				RSA_meth_set_keygen(pkcs11_rsa,
						pkcs11_RSA_generate_key);
#endif
				ENGINE_set_load_privkey_function(e, pkcs11_load_privkey);
				ENGINE_set_load_pubkey_function(e, pkcs11_load_pubkey);
#endif
				break; 
			case CKM_DH_PKCS_KEY_PAIR_GEN:
			case CKM_DH_PKCS_DERIVE:
			case CKM_X9_42_DH_KEY_PAIR_GEN:
			case CKM_X9_42_DH_DERIVE:
			case CKM_X9_42_DH_HYBRID_DERIVE:
			case CKM_DH_PKCS_PARAMETER_GEN:
			case CKM_X9_42_DH_PARAMETER_GEN:
				break;
			case CKM_DES_ECB:
				tok->pkcs11_implemented_ciphers[NID_des_ecb] = 1;
				num_cipher_nids++;
				break;
			case CKM_DES_CBC:
			case CKM_DES_CBC_PAD:
				tok->pkcs11_implemented_ciphers[NID_des_cbc] = 1;
				num_cipher_nids++;
				break;
			case CKM_DES_KEY_GEN:
			case CKM_DES_MAC:
			case CKM_DES_MAC_GENERAL:
				break; 
			case CKM_DES3_ECB:
				tok->pkcs11_implemented_ciphers[NID_des_ede3_ecb] = 1;
				num_cipher_nids++;
				break;
			case CKM_DES3_CBC:
			case CKM_DES3_CBC_PAD:
				tok->pkcs11_implemented_ciphers[NID_des_ede3_cbc] = 1;
				num_cipher_nids++;
				break;
			case CKM_DES3_KEY_GEN:
			case CKM_DES3_MAC:
			case CKM_DES3_MAC_GENERAL:
				break; 
			case CKM_SHA_1:
				tok->pkcs11_implemented_digests[NID_sha1] = 1;
				num_digest_nids++;
				break;
			case CKM_SHA_1_HMAC:
			case CKM_SHA_1_HMAC_GENERAL:
				tok->pkcs11_implemented_digests[NID_hmacWithSHA1] = 1;
				num_digest_nids++;
				break;
			case CKM_PBA_SHA1_WITH_SHA1_HMAC:
			case CKM_SHA1_KEY_DERIVATION:
			case CKM_SHA1_RSA_PKCS:
				tok->pkcs11_implemented_digests[NID_sha1WithRSAEncryption] = 1;
				num_digest_nids++;
				break; 
				
			case CKM_SHA224:
				tok->pkcs11_implemented_digests[NID_sha224] = 1;
				num_digest_nids++;
				break;
			case CKM_SHA224_KEY_DERIVATION:
			case CKM_SHA224_RSA_PKCS:
				tok->pkcs11_implemented_digests[NID_sha224WithRSAEncryption] = 1;
				num_digest_nids++;
				break; 
				
				
			case CKM_SHA256:
				tok->pkcs11_implemented_digests[NID_sha256] = 1;
				num_digest_nids++;
				break;
			case CKM_SHA256_KEY_DERIVATION:
			case CKM_SHA256_RSA_PKCS:
				tok->pkcs11_implemented_digests[NID_sha256WithRSAEncryption] = 1;
				num_digest_nids++;
				break; 
				
			case CKM_SHA384:
				tok->pkcs11_implemented_digests[NID_sha384] = 1;
				num_digest_nids++;
				break;
			case CKM_SHA384_KEY_DERIVATION:
			case CKM_SHA384_RSA_PKCS:
				tok->pkcs11_implemented_digests[NID_sha384WithRSAEncryption] = 1;
				num_digest_nids++;
				break; 
			case CKM_SHA512:
				tok->pkcs11_implemented_digests[NID_sha512] = 1;
				num_digest_nids++;
				break;
			case CKM_SHA512_KEY_DERIVATION:
			case CKM_SHA512_RSA_PKCS:
				tok->pkcs11_implemented_digests[NID_sha512WithRSAEncryption] = 1;
				num_digest_nids++;
				break; 
				
			case CKM_AES_ECB:
				tok->pkcs11_implemented_ciphers[NID_aes_128_ecb] = 1;
				tok->pkcs11_implemented_ciphers[NID_aes_192_ecb] = 1;
				tok->pkcs11_implemented_ciphers[NID_aes_256_ecb] = 1;
				num_cipher_nids += 3;
				break;
			case CKM_AES_KEY_GEN:
				break;
			case CKM_AES_CBC_PAD:
			case CKM_AES_CBC:
				tok->pkcs11_implemented_ciphers[NID_aes_128_cbc] = 1;
				tok->pkcs11_implemented_ciphers[NID_aes_192_cbc] = 1;
				tok->pkcs11_implemented_ciphers[NID_aes_256_cbc] = 1;
				num_cipher_nids += 3;
				break;
			case CKM_AES_MAC:
			case CKM_AES_MAC_GENERAL:
				break; 
			case CKM_MD5:
				tok->pkcs11_implemented_digests[NID_md5] = 1;
				num_digest_nids++;
				break;
			case CKM_MD5_HMAC:
			case CKM_MD5_HMAC_GENERAL:
			case CKM_SSL3_PRE_MASTER_KEY_GEN:
			case CKM_SSL3_MASTER_KEY_DERIVE:
			case CKM_SSL3_KEY_AND_MAC_DERIVE:
			case CKM_SSL3_MD5_MAC:
			case CKM_SSL3_SHA1_MAC:
				break;
			case CKM_RIPEMD160:
				tok->pkcs11_implemented_digests[NID_ripemd160] = 1;
				num_digest_nids++;
				break;
			case CKM_RIPEMD160_HMAC:
			case CKM_RIPEMD160_HMAC_GENERAL:
				break;
			default:
				DBG_fprintf("The token in slot %lx has reported that it can "
					    "perform\nmechanism 0x%lx, which is not available to "
					    "accelerate in openssl.\n", tok->slot_id, mech_list[i]);
				break;
		}
	}

err_free:
	OPENSSL_free(mech_list);
err:
	return;
}

/* Add a new token struct to the list 
 * This is called during the bind_pkcs11, in other words after openSSL has
 * decided to use us for some operation.
 */
struct _token *pkcs11_addToken(CK_SLOT_ID slot_id)
{
	struct _token *new_tok = (struct _token *) OPENSSL_malloc(sizeof(struct _token));

	if (new_tok == NULL) {
		PKCS11err(PKCS11_F_ADDTOKEN, PKCS11_R_MALLOC_FAILURE);
		return NULL;
	}

	memset(new_tok, 0, sizeof(struct _token));
	new_tok->slot_id = slot_id;

	new_tok->token_next = pkcs11_token_list;
	pkcs11_token_list = new_tok;

	return new_tok;
}

/*
 * pre_init_pkcs11:  this is called at openSSL startup.  Here is where we
 * try to convince openSSL to use us.  If it decides not to, there is no
 * guarantee that we will ever be asked to clean up.  So everything we
 * do must be self-contained.
 */
static int pre_init_pkcs11(ENGINE *e)
{
	CK_C_GetFunctionList p;
	CK_RV rv = CKR_OK;
	CK_INFO Info;
	CK_SLOT_ID_PTR pSlotList;
	CK_ULONG ulSlotCount;
	CK_SLOT_INFO slotInfo;
	struct _token *tok;
	int i;

	if(pkcs11_dso)
	{
		PKCS11err(PKCS11_F_PREINIT, PKCS11_R_ALREADY_LOADED);
		goto err;
	}

	/* Attempt to load PKCS#11 library */
	pkcs11_dso = dlopen(get_PKCS11_LIBNAME(), RTLD_NOW);

	if(pkcs11_dso == NULL)
	{
		PKCS11err(PKCS11_F_PREINIT, PKCS11_R_DSO_FAILURE);
		goto err;
	}

	/* get the C_GetFunctionList function from the loaded library */
	p = (CK_C_GetFunctionList)dlsym(pkcs11_dso, PKCS11_GET_FUNCTION_LIST);
	if ( !p )
	{
		PKCS11err(PKCS11_F_PREINIT, PKCS11_R_DSO_FAILURE);
		goto err;
	}

	/* get the full function list from the loaded library */
	rv = p(&pFunctionList);
	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_PREINIT, PKCS11_R_DSO_FAILURE, rv);
		goto err;
	}

#ifdef BULL_CRYPTOBOX
	/* the address of the CryptoBox is in /etc/CryptoBox */
	rv = C_InitializeRpc (NULL, NULL, NULL);
	if (rv != CKR_OK)
		goto err;
#endif

	/* Initialize Cryptoki */
	rv = pFunctionList->C_Initialize(NULL_PTR);
	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED))
	{
		pkcs11_die(PKCS11_F_PREINIT, PKCS11_R_INITIALIZE, rv);
		goto err;
	}
	rv = pFunctionList->C_GetInfo(&Info);
	if (rv != CKR_OK) 
	{
		pkcs11_die(PKCS11_F_PREINIT, PKCS11_R_GETINFO, rv);
		pFunctionList->C_Finalize(NULL);
		goto err;
	}

 	if (strncmp((char *)Info.libraryDescription, BULL_TRUSTWAY_LIBRARY_DESCRIPTION, 32))
	{
		rv = pFunctionList->C_GetSlotList(TRUE, NULL_PTR, &ulSlotCount);
		if ((rv != CKR_OK) || (ulSlotCount == 0)) 
		{
			pkcs11_die(PKCS11_F_PREINIT, PKCS11_R_GETSLOTLIST, rv);
		}
		else
		{
			pSlotList = (CK_SLOT_ID_PTR) OPENSSL_malloc(ulSlotCount * sizeof(CK_SLOT_ID));
			if ( pSlotList != NULL)
			{
				rv = pFunctionList->C_GetSlotList(TRUE, pSlotList, &ulSlotCount);
				if (rv != CKR_OK) 
				{
					pkcs11_die(PKCS11_F_PREINIT, PKCS11_R_GETSLOTLIST, rv);
					pFunctionList->C_Finalize(NULL);
					OPENSSL_free(pSlotList);
					goto err;
				}

				/* Check each slot to see if there's a hardware token present.
				*/
				for (i = 0; i < ulSlotCount; i++)
				{
					rv = pFunctionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
					if (rv != CKR_OK)
					{
						pkcs11_die(PKCS11_F_PREINIT, PKCS11_R_GETSLOTINFO,
							   rv);
						pFunctionList->C_Finalize(NULL);
						OPENSSL_free(pSlotList);
						goto err;
					}

					/* we're mallocing memory here that may need to be freed
					 * if openssl chooses not to use us. We'll free it in
					 * the library destructor, pkcs11_engine_destructor */
					tok = pkcs11_addToken(pSlotList[i]);
					pkcs11_regToken(e, tok);
				}
				OPENSSL_free(pSlotList);
			}
		}
	}
	else
	{
		/* Bull Trustway CC2000 crypto hardware detected */
		Bull_TrustWay = TRUE;
		SLOTID = 0xFFFFFFFF;
	}

	/* Finish with Cryptoki:  We will restart if openSSL calls one of our
	 * functions */
	pFunctionList->C_Finalize(NULL);
	dlclose(pkcs11_dso);
	pkcs11_dso = NULL;

	return 1;

err:
	if(pkcs11_dso)
		dlclose(pkcs11_dso);
	pkcs11_dso = NULL;
	return 0;
}

/* initialization function */
/* This is called when openSSL has decided to use us, and warns us to
 * initialize.  pkcs11_finish will be called when all is done.  */
static int pkcs11_init(ENGINE *e)
{
	CK_C_GetFunctionList p;
	CK_RV rv = CKR_OK;
	CK_INFO Info;
	CK_SLOT_ID_PTR pSlotList;
	CK_ULONG ulSlotCount;
	CK_SLOT_INFO slotInfo;
	int i;

	if(pkcs11_dso)
	{
		PKCS11err(PKCS11_F_INIT, PKCS11_R_ALREADY_LOADED);
		goto err;
	}

	/* Attempt to load PKCS#11 library */
	pkcs11_dso = dlopen(get_PKCS11_LIBNAME(), RTLD_NOW);

	if(pkcs11_dso == NULL)
	{
		PKCS11err(PKCS11_F_INIT, PKCS11_R_DSO_FAILURE);
		goto err;
	}

	/* get the C_GetFunctionList function from the loaded library */
	p = (CK_C_GetFunctionList)dlsym(pkcs11_dso, PKCS11_GET_FUNCTION_LIST);
	if ( !p )
	{
		PKCS11err(PKCS11_F_INIT, PKCS11_R_DSO_FAILURE);
		goto err;
	}

	/* get the full function list from the loaded library */
	rv = p(&pFunctionList);
	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_INIT, PKCS11_R_DSO_FAILURE, rv);
		goto err;
	}

#ifdef BULL_CRYPTOBOX
	/* the address of the CryptoBox is in /etc/CryptoBox */
	rv = C_InitializeRpc (NULL, NULL, NULL);
	if (rv != CKR_OK)
		goto err;
#endif

	rv = pFunctionList->C_Initialize(NULL_PTR);
	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED))
	{
		pkcs11_die(PKCS11_F_INIT, PKCS11_R_INITIALIZE, rv);
		goto err;
	}
	rv = pFunctionList->C_GetInfo(&Info);
	if (rv != CKR_OK) 
	{
		pkcs11_die(PKCS11_F_INIT, PKCS11_R_GETINFO, rv);
		pFunctionList->C_Finalize(NULL);
		goto err;
	}

	if (strncmp((char *)Info.libraryDescription, BULL_TRUSTWAY_LIBRARY_DESCRIPTION, 32))
	{
		rv = pFunctionList->C_GetSlotList(TRUE, NULL_PTR, &ulSlotCount);
		if ((rv != CKR_OK) || (ulSlotCount == 0)) 
		{
			pkcs11_die(PKCS11_F_INIT, PKCS11_R_GETSLOTLIST, rv);
		}
		else
		{
			pSlotList = (CK_SLOT_ID_PTR) OPENSSL_malloc(ulSlotCount * sizeof(CK_SLOT_ID));
			if ( pSlotList != NULL)
			{
				rv = pFunctionList->C_GetSlotList(TRUE, pSlotList, &ulSlotCount);
				if (rv != CKR_OK) 
				{
					pkcs11_die(PKCS11_F_INIT, PKCS11_R_GETSLOTLIST, rv);
					pFunctionList->C_Finalize(NULL);
					OPENSSL_free(pSlotList);
					goto err;
				}

				/* Check each slot to see if there's a hardware token present.
				*/
				for (i = 0; i < ulSlotCount; i++)
				{
					rv = pFunctionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
					if (rv != CKR_OK)
					{
						pkcs11_die(PKCS11_F_INIT, PKCS11_R_GETSLOTINFO, rv);
						pFunctionList->C_Finalize(NULL);
						OPENSSL_free(pSlotList);
						goto err;
					}

					pkcs11_addToken(pSlotList[i]);
				}
				OPENSSL_free(pSlotList);
			}
		}
	}
	else
	{
		/* Bull Trustway CC2000 crypto hardware detected */
		Bull_TrustWay = TRUE;
		SLOTID = 0xFFFFFFFF;
	}

#ifndef OPENSSL_NO_RSA
	/* Everything's fine. */
	if (rsaPubKey == -1)
		rsaPubKey = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	if (rsaPrivKey == -1)
		rsaPrivKey = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	if (deletePubKeyOnFree == -1)
		deletePubKeyOnFree = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	if (deletePrivKeyOnFree == -1)
		deletePrivKeyOnFree = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	if (pkcs11Session == -1)
		pkcs11Session = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);
#endif

	if (pkcs11_token_list == NULL)
		PKCS11err(PKCS11_F_INIT, PKCS11_R_NOTOKENS);

	PKCS11_Initialized = 1;

	/* TODO:  This should only be done on linux systems */
	pthread_atfork(NULL, NULL, (void(*)())pkcs11_atfork_init);

	return 1;

err:
	if(pkcs11_dso)
		dlclose(pkcs11_dso);
	pkcs11_dso = NULL;
	return 0;
}

/* Destructor (complements the "ENGINE_pkcs11()" constructor) */
/* XXX HUH?  Can we just DSO_load once, then??? */
static int pkcs11_destroy(ENGINE *e)
{
	DBG_fprintf("%s: called\n", __FUNCTION__);

#ifndef OLDER_OPENSSL
	pkcs11_des_ecb_destroy();
	pkcs11_des_cbc_destroy();
	pkcs11_tdes_ecb_destroy();
	pkcs11_tdes_cbc_destroy();
	pkcs11_aes_128_cbc_destroy();
	pkcs11_aes_192_cbc_destroy();
	pkcs11_aes_256_cbc_destroy();
	pkcs11_aes_128_ecb_destroy();
	pkcs11_aes_192_ecb_destroy();
	pkcs11_aes_256_ecb_destroy();
	pkcs11_sha1_destroy();
	pkcs11_sha224_destroy();
	pkcs11_sha256_destroy();
	pkcs11_sha384_destroy();
	pkcs11_sha512_destroy();
	pkcs11_md5_destroy();
	pkcs11_ripemd160_destroy();
#endif

	free_PKCS11_LIBNAME();
	ERR_unload_pkcs11_strings();
	return 1;
}

/* termination function */
static int pkcs11_finish(ENGINE *e)
{
	struct _token *tmp;

	if(pkcs11_dso == NULL)
	{
		PKCS11err(PKCS11_F_FINISH, PKCS11_R_NOT_LOADED);
		goto err;
	}
	assert(pFunctionList != NULL);

	while (pkcs11_token_list) {
		tmp = pkcs11_token_list->token_next;
		OPENSSL_free(pkcs11_token_list);
		pkcs11_token_list = tmp;
	}

	pFunctionList->C_Finalize(NULL);

	if(dlclose(pkcs11_dso))
	{	PKCS11err(PKCS11_F_FINISH, PKCS11_R_DSO_FAILURE);
		goto err;
	}
	pkcs11_dso = NULL;
	pFunctionList = NULL;

	return 1;

err:
	pkcs11_dso = NULL;
	pFunctionList = NULL;
	return 0;
}

static int pkcs11_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
{
	int initialized = ((pkcs11_dso == NULL) ? 0 : 1);
	struct _token *tok;

	switch(cmd)
	{
		case PKCS11_CMD_SO_PATH:
			if(p == NULL)
			{
				PKCS11err(PKCS11_F_CTRL, ERR_R_PASSED_NULL_PARAMETER);
				return 0;
			}
			if(initialized)
			{
				PKCS11err(PKCS11_F_CTRL, PKCS11_R_ALREADY_LOADED);
				return 0;
			}
			return set_PKCS11_LIBNAME((const char*)p);
		case PKCS11_CMD_SLOT_ID:
			tok = pkcs11_token_list;
			while (tok) {
				if (tok->slot_id == i) {
					pkcs11_token = tok;
					DBG_fprintf("slot %ld selected\n", i);
					return 1;
				}
				tok = tok->token_next;
			}
			PKCS11err(PKCS11_F_CTRL, PKCS11_R_TOKEN_NOT_AVAILABLE);
			return 0;
		default:
			break;
	}
	PKCS11err(PKCS11_F_CTRL,PKCS11_R_CTRL_COMMAND_NOT_IMPLEMENTED);
	return 0;
}

#ifndef OPENSSL_NO_RSA
CK_OBJECT_HANDLE pkcs11_FindOrCreateKey(CK_SESSION_HANDLE  h,
					RSA               *rsa,
					CK_OBJECT_CLASS    oKey,
					CK_BBOOL           fKeyCreate)
{
	CK_RV rv;
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
	CK_ULONG Matches;
	CK_KEY_TYPE kType = CKK_RSA;
	CK_ULONG ulKeyAttributeCount;

#ifndef OLDER_OPENSSL
	const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
#endif

	CK_ATTRIBUTE  pubKeyTemplate[] =
	{
		{CKA_CLASS, &oKey, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, &kType, sizeof(CK_KEY_TYPE)},
		{CKA_MODULUS, (void *)NULL, 0},
		{CKA_PUBLIC_EXPONENT, (void *)NULL, 0},
	};
	CK_ATTRIBUTE  privKeyTemplate[] =
	{
		{CKA_CLASS, &oKey, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, &kType, sizeof(CK_KEY_TYPE)},
		{CKA_MODULUS, (void *)NULL, 0},
		{CKA_PUBLIC_EXPONENT, (void *)NULL, 0},
		{CKA_PRIVATE_EXPONENT, (void *)NULL, 0},
		{CKA_PRIME_1, (void *)NULL, 0},
		{CKA_PRIME_2, (void *)NULL, 0},
		{CKA_EXPONENT_1, (void *)NULL, 0},
		{CKA_EXPONENT_2, (void *)NULL, 0},
		{CKA_COEFFICIENT, (void *)NULL, 0}
	};
	long  deletePubKey;

	DBG_fprintf("%s\n", __FUNCTION__);

	if (oKey == CKO_PUBLIC_KEY) {
		DBG_fprintf("looking up a public key\n");

#ifdef OLDER_OPENSSL
		pubKeyTemplate[2].ulValueLen = BN_num_bytes(rsa->n);
		pubKeyTemplate[3].ulValueLen = BN_num_bytes(rsa->e);
#else
		RSA_get0_key(rsa, &n, &e, NULL);
		pubKeyTemplate[2].ulValueLen = BN_num_bytes(n);
		pubKeyTemplate[3].ulValueLen = BN_num_bytes(e);
#endif

		pubKeyTemplate[2].pValue = (CK_VOID_PTR)OPENSSL_malloc(
				(size_t)pubKeyTemplate[2].ulValueLen);
		pubKeyTemplate[3].pValue = (CK_VOID_PTR)OPENSSL_malloc(
				(size_t)pubKeyTemplate[3].ulValueLen);

#ifdef OLDER_OPENSSL
		BN_bn2bin(rsa->n, pubKeyTemplate[2].pValue);
		BN_bn2bin(rsa->e, pubKeyTemplate[3].pValue);
#else
		BN_bn2bin(n, pubKeyTemplate[2].pValue);
		BN_bn2bin(e, pubKeyTemplate[3].pValue);
#endif

		ulKeyAttributeCount = 4;
		rv = pFunctionList->C_FindObjectsInit(h, pubKeyTemplate, ulKeyAttributeCount);
	} else {
		DBG_fprintf("looking up a private key\n");

#ifdef OLDER_OPENSSL
		privKeyTemplate[2].ulValueLen = BN_num_bytes(rsa->n);
		privKeyTemplate[3].ulValueLen = BN_num_bytes(rsa->e);
		privKeyTemplate[4].ulValueLen = BN_num_bytes(rsa->d);
		privKeyTemplate[5].ulValueLen = BN_num_bytes(rsa->p);
		privKeyTemplate[6].ulValueLen = BN_num_bytes(rsa->q);
		privKeyTemplate[7].ulValueLen = BN_num_bytes(rsa->dmp1);
		privKeyTemplate[8].ulValueLen = BN_num_bytes(rsa->dmq1);
		privKeyTemplate[9].ulValueLen = BN_num_bytes(rsa->iqmp);
#else
		RSA_get0_key(rsa, &n, &e, &d);
		RSA_get0_factors(rsa, &p, &q);
		RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
		privKeyTemplate[2].ulValueLen = BN_num_bytes(n);
		privKeyTemplate[3].ulValueLen = BN_num_bytes(e);
		privKeyTemplate[4].ulValueLen = BN_num_bytes(d);
		privKeyTemplate[5].ulValueLen = BN_num_bytes(p);
		privKeyTemplate[6].ulValueLen = BN_num_bytes(q);
		privKeyTemplate[7].ulValueLen = BN_num_bytes(dmp1);
		privKeyTemplate[8].ulValueLen = BN_num_bytes(dmq1);
		privKeyTemplate[9].ulValueLen = BN_num_bytes(iqmp);
#endif

		privKeyTemplate[2].pValue = (CK_VOID_PTR)OPENSSL_malloc(
				(size_t)privKeyTemplate[2].ulValueLen);
		privKeyTemplate[3].pValue = (CK_VOID_PTR)OPENSSL_malloc(
				(size_t)privKeyTemplate[3].ulValueLen);
		privKeyTemplate[4].pValue = (CK_VOID_PTR)OPENSSL_malloc(
				(size_t)privKeyTemplate[4].ulValueLen);
		privKeyTemplate[5].pValue = (CK_VOID_PTR)OPENSSL_malloc(
				(size_t)privKeyTemplate[5].ulValueLen);
		privKeyTemplate[6].pValue = (CK_VOID_PTR)OPENSSL_malloc(
				(size_t)privKeyTemplate[6].ulValueLen);
		privKeyTemplate[7].pValue = (CK_VOID_PTR)OPENSSL_malloc(
				(size_t)privKeyTemplate[7].ulValueLen);
		privKeyTemplate[8].pValue = (CK_VOID_PTR)OPENSSL_malloc(
				(size_t)privKeyTemplate[8].ulValueLen);
		privKeyTemplate[9].pValue = (CK_VOID_PTR)OPENSSL_malloc(
				(size_t)privKeyTemplate[9].ulValueLen);

#ifdef OLDER_OPENSSL
		BN_bn2bin(rsa->n, privKeyTemplate[2].pValue);
		BN_bn2bin(rsa->e, privKeyTemplate[3].pValue);
		BN_bn2bin(rsa->d, privKeyTemplate[4].pValue);
		BN_bn2bin(rsa->p, privKeyTemplate[5].pValue);
		BN_bn2bin(rsa->q, privKeyTemplate[6].pValue);
		BN_bn2bin(rsa->dmp1, privKeyTemplate[7].pValue);
		BN_bn2bin(rsa->dmq1, privKeyTemplate[8].pValue);
		BN_bn2bin(rsa->iqmp, privKeyTemplate[9].pValue);
#else
		BN_bn2bin(n, privKeyTemplate[2].pValue);
		BN_bn2bin(e, privKeyTemplate[3].pValue);
		BN_bn2bin(d, privKeyTemplate[4].pValue);
		BN_bn2bin(p, privKeyTemplate[5].pValue);
		BN_bn2bin(q, privKeyTemplate[6].pValue);
		BN_bn2bin(dmp1, privKeyTemplate[7].pValue);
		BN_bn2bin(dmq1, privKeyTemplate[8].pValue);
		BN_bn2bin(iqmp, privKeyTemplate[9].pValue);
#endif

		ulKeyAttributeCount = 10;
		rv = pFunctionList->C_FindObjectsInit(h, privKeyTemplate, ulKeyAttributeCount);
	}

	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_FINDORCREATEKEY, PKCS11_R_FINDOBJECTSINIT, rv);
		goto err;
	}
	rv = pFunctionList->C_FindObjects(h, &hKey, 1, &Matches);
	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_FINDORCREATEKEY, PKCS11_R_FINDOBJECTS, rv);
		goto err;
	}
	rv = pFunctionList->C_FindObjectsFinal(h);
	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_FINDORCREATEKEY, PKCS11_R_FINDOBJECTSFINAL, rv);
		goto err;
	}
	/* Assume there should be no more than one match */
	if (Matches == 0)
	{
		DBG_fprintf("matches was 0, creating this key\n");
#ifdef OLDER_OPENSSL
		DBG_fprintf("rsa->n is %d bytes\n", BN_num_bytes(rsa->n));
#else
		DBG_fprintf("rsa->n is %d bytes\n", BN_num_bytes(n));
#endif
		if (fKeyCreate &&
#ifdef OLDER_OPENSSL
		    BN_num_bytes(rsa->n)
#else
		    BN_num_bytes(n)
#endif
		   ) {
			if (oKey == CKO_PUBLIC_KEY)
				rv = pFunctionList->C_CreateObject(h, pubKeyTemplate,
								   ulKeyAttributeCount, &hKey);
			else
				rv = pFunctionList->C_CreateObject(h, privKeyTemplate,
								   ulKeyAttributeCount, &hKey);
			if (rv != CKR_OK)
			{
				DBG_fprintf("error creating key object.\n");
				pkcs11_die(PKCS11_F_FINDORCREATEKEY, PKCS11_R_CREATEOBJECT, rv);
				goto err;
			}
			else
			{
				DBG_fprintf("key obj created\n");
				deletePubKey = TRUE;
				if (oKey == CKO_PUBLIC_KEY)
					RSA_set_ex_data(rsa, deletePubKeyOnFree,
							(void *)deletePubKey);
				else
					RSA_set_ex_data(rsa, deletePrivKeyOnFree,
							(void *)deletePubKey);
			}
		}
		else
		{
			PKCS11err(PKCS11_F_FINDORCREATEKEY, PKCS11_R_OBJECT_NOT_FOUND);
			goto err;
		}
	}
	if (oKey == CKO_PUBLIC_KEY)
		RSA_set_ex_data(rsa, rsaPubKey, (char *)hKey);
	if (oKey == CKO_PRIVATE_KEY)
		RSA_set_ex_data(rsa, rsaPrivKey, (char *)hKey);

err:
	if (oKey == CKO_PUBLIC_KEY) {
		if (pubKeyTemplate[2].pValue != NULL)
		{
			OPENSSL_free(pubKeyTemplate[2].pValue);
			pubKeyTemplate[2].pValue = NULL;
		}

		if (pubKeyTemplate[3].pValue != NULL)
		{
			OPENSSL_free(pubKeyTemplate[3].pValue);
			pubKeyTemplate[3].pValue = NULL;
		}
	} else {
		if (privKeyTemplate[2].pValue != NULL)
		{
			OPENSSL_free(privKeyTemplate[2].pValue);
			privKeyTemplate[2].pValue = NULL;
		}

		if (privKeyTemplate[3].pValue != NULL)
		{
			OPENSSL_free(privKeyTemplate[3].pValue);
			privKeyTemplate[3].pValue = NULL;
		}

		if (privKeyTemplate[4].pValue != NULL)
		{
			OPENSSL_free(privKeyTemplate[4].pValue);
			privKeyTemplate[4].pValue = NULL;
		}

		if (privKeyTemplate[5].pValue != NULL)
		{
			OPENSSL_free(privKeyTemplate[5].pValue);
			privKeyTemplate[5].pValue = NULL;
		}

		if (privKeyTemplate[6].pValue != NULL)
		{
			OPENSSL_free(privKeyTemplate[6].pValue);
			privKeyTemplate[6].pValue = NULL;
		}

		if (privKeyTemplate[7].pValue != NULL)
		{
			OPENSSL_free(privKeyTemplate[7].pValue);
			privKeyTemplate[7].pValue = NULL;
		}

		if (privKeyTemplate[8].pValue != NULL)
		{
			OPENSSL_free(privKeyTemplate[8].pValue);
			privKeyTemplate[8].pValue = NULL;
		}

		if (privKeyTemplate[9].pValue != NULL)
		{
			OPENSSL_free(privKeyTemplate[9].pValue);
			privKeyTemplate[9].pValue = NULL;
		}
	}

	return hKey;

}

/*----------------------------------------------------------------*/
/* pkcs11_RSA_public_encrypt */
/* */
/* This function implements RSA public encryption. 'from_len'
   bytes taken from 'from' and encrypted and put into 'to'. 'to' needs
   to be at least RSA_size(rsa) bytes long. The number of bytes
   written into 'to' is returned. -1 is returned on an error. The
   operation performed is to = from^rsa->e mod rsa->n. */
/* for PKCS11, use C_EncryptInit + C_Encrypt */
/*----------------------------------------------------------------*/
static int pkcs11_RSA_public_encrypt(int flen,
		const unsigned char *from,
		unsigned char *to,
		RSA *rsa,
		int padding)
{
	CK_ULONG bytesEncrypted=0;
	CK_RV rv;
	CK_MECHANISM Mechanism_rsa = {CKM_RSA_PKCS, NULL, 0};
	CK_MECHANISM *pMechanism = &Mechanism_rsa;
	CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
	struct token_session *wrapper = NULL;
	CK_SESSION_HANDLE session;

	DBG_fprintf("%s\n", __FUNCTION__);

	if (padding != RSA_PKCS1_PADDING)
	{
		PKCS11err(PKCS11_F_RSA_PUB_ENC, PKCS11_R_UNKNOWN_PADDING_TYPE);
		return -1;
	}

	session = (CK_SESSION_HANDLE)RSA_get_ex_data(rsa, pkcs11Session);
	if (session == CK_INVALID_HANDLE || !session) {
		wrapper = pkcs11_getSession();
		if (!wrapper)
			return 0;

		DBG_fprintf("%d: created new session\n", __LINE__);
		session = wrapper->session;
		RSA_set_ex_data(rsa, pkcs11Session, (void *)session);
	}

	hPublicKey = (CK_OBJECT_HANDLE)RSA_get_ex_data(rsa, rsaPubKey);
	if (hPublicKey == CK_INVALID_HANDLE)
		hPublicKey = pkcs11_FindOrCreateKey(session, rsa, CKO_PUBLIC_KEY, true);


	if (hPublicKey != CK_INVALID_HANDLE)
	{
		rv = pFunctionList->C_EncryptInit(session, pMechanism, hPublicKey);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PUB_ENC, PKCS11_R_ENCRYPTINIT, rv);
			bytesEncrypted = -1;
			goto out;
		}

		rv = pFunctionList->C_Encrypt(session, (unsigned char *)from,
				flen, NULL_PTR, &bytesEncrypted);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PUB_ENC, PKCS11_R_ENCRYPT, rv);
			bytesEncrypted = -1;
			goto out;
		}

		rv = pFunctionList->C_Encrypt(session, (unsigned char *)from,
				flen, to, &bytesEncrypted);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PUB_ENC, PKCS11_R_ENCRYPT, rv);
			bytesEncrypted = -1;
			goto out;
		}
	}


out:
	OPENSSL_free(wrapper);
	return bytesEncrypted;
}



/*----------------------------------------------------------------*/
/* pkcs11_RSA_private_encrypt */
/* This function implements RSA private encryption.
   That corresponds to a signature and only the RSA_PKCS1_PADDING
   is supported.
flen : bytes taken from 'from' and encrypted and put into 'to'.
to : needs to be at least bytes long.
ret : returns the number of bytes written into 'to' or -1 if an error.
for PKCS11 use C_SignInit + C_Sign */
/*----------------------------------------------------------------*/
static int pkcs11_RSA_private_encrypt(int flen,
		const unsigned char *from,
		unsigned char *to,
		RSA *rsa,
		int padding)
{
	CK_ULONG ulSignatureLen=0;
	CK_RV rv;
	CK_MECHANISM Mechanism_rsa = {CKM_RSA_PKCS, NULL, 0};
	CK_MECHANISM *pMechanism = &Mechanism_rsa;
	CK_OBJECT_HANDLE hPrivateKey= CK_INVALID_HANDLE;
	struct token_session *wrapper = NULL;
	CK_SESSION_HANDLE session;

	DBG_fprintf("%s\n", __FUNCTION__);

	if (padding != RSA_PKCS1_PADDING)
	{
		PKCS11err(PKCS11_F_RSA_PRIV_ENC, PKCS11_R_UNKNOWN_PADDING_TYPE);
		return -1;
	}

	session = (CK_SESSION_HANDLE)RSA_get_ex_data(rsa, pkcs11Session);
	if (session == CK_INVALID_HANDLE || !session) {
		wrapper = pkcs11_getSession();
		if (!wrapper)
			return 0;

		DBG_fprintf("%d: created new session\n", __LINE__);
		session = wrapper->session;
		RSA_set_ex_data(rsa, pkcs11Session, (void *)session);
	}

	hPrivateKey = (CK_OBJECT_HANDLE)RSA_get_ex_data(rsa, rsaPrivKey);
	if (hPrivateKey == CK_INVALID_HANDLE)
		hPrivateKey = pkcs11_FindOrCreateKey(session, rsa, CKO_PRIVATE_KEY, true);

	if (hPrivateKey != CK_INVALID_HANDLE)
	{
		rv = pFunctionList->C_SignInit(session, pMechanism, hPrivateKey);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PRIV_ENC, PKCS11_R_SIGNINIT, rv);
			ulSignatureLen = -1;
			goto out;
		}

		rv = pFunctionList->C_Sign(session, (unsigned char *)from,
				flen, NULL_PTR, &ulSignatureLen);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PRIV_ENC, PKCS11_R_SIGN, rv);
			ulSignatureLen = -1;
			goto out;
		}

		rv = pFunctionList->C_Sign(session, (unsigned char *)from,
				flen, to, &ulSignatureLen);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PRIV_ENC, PKCS11_R_SIGN, rv);
			ulSignatureLen = -1;
			goto out;
		}
	}

out:
	OPENSSL_free(wrapper);
	return ulSignatureLen;
}



/*----------------------------------------------------------------*/
/* pkcs11_RSA_private_decrypt */
/* */
/*This function implements RSA private decryption.

flen : bytes are taken from 'from' and decrypted.
The decrypted data is put into 'to'. 
ret : returns the number of bytes -1 if an error.
The operation performed is to = from^rsa->d mod rsa->n.*/
/* for PKCS11 use C_DecryptInit + C_Decrypt */
/*----------------------------------------------------------------*/
static int pkcs11_RSA_private_decrypt(int flen,
		const unsigned char *from,
		unsigned char *to,
		RSA *rsa,
		int padding)
{
	CK_ULONG bytesDecrypted = flen;
	CK_RV rv;
	CK_MECHANISM Mechanism_rsa = {CKM_RSA_PKCS, NULL, 0};
	CK_MECHANISM *pMechanism = &Mechanism_rsa;
	CK_OBJECT_HANDLE hPrivateKey;
	struct token_session *wrapper = NULL;
	CK_SESSION_HANDLE session;

	DBG_fprintf("%s\n", __FUNCTION__);

	if (padding != RSA_PKCS1_PADDING)
	{
		PKCS11err(PKCS11_F_RSA_PRIV_DEC, PKCS11_R_UNKNOWN_PADDING_TYPE);
		return -1;
	}

	session = (CK_SESSION_HANDLE)RSA_get_ex_data(rsa, pkcs11Session);
	if (session == CK_INVALID_HANDLE || !session) {
		wrapper = pkcs11_getSession();
		if (!wrapper)
			return 0;

		DBG_fprintf("%d: created new session\n", __LINE__);
		session = wrapper->session;
		RSA_set_ex_data(rsa, pkcs11Session, (void *)session);
	}

	hPrivateKey = (CK_OBJECT_HANDLE)RSA_get_ex_data(rsa, rsaPrivKey);
	if (hPrivateKey == CK_INVALID_HANDLE)
		hPrivateKey = pkcs11_FindOrCreateKey(session, rsa, CKO_PRIVATE_KEY, true);

	if (hPrivateKey != CK_INVALID_HANDLE)
	{
		rv = pFunctionList->C_DecryptInit(session, pMechanism, hPrivateKey);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PRIV_DEC, PKCS11_R_DECRYPTINIT, rv);
			bytesDecrypted = -1;
			goto out;
		}

		rv = pFunctionList->C_Decrypt(session, (unsigned char *)from,
				flen, to, &bytesDecrypted);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PRIV_DEC, PKCS11_R_DECRYPT, rv);
			bytesDecrypted = -1;
			goto out;
		}
	}
out:
	OPENSSL_free(wrapper);
	return bytesDecrypted;
}



/*----------------------------------------------------------------*/
/* pkcs11_RSA_public_decrypt */
/* */
/* This function implements RSA public decryption, the rsaKey
   variable is the public key (but can be a private key).
   This function should be processed as a pkcs11
   verify-recover function
flen : bytes are taken from 'from' and decrypted.
to : The decrypted data.
ret : The number of bytes encrypted. -1 is returned to indicate an error.
The operation performed is to = from^rsa->e mod rsa->n.*/
/* for PKCS11 use C_VerifyRecoverInit + C_VerifyRecover */
/*'from' points to signature and 'flen' contains its length*/
/*----------------------------------------------------------------*/
static int pkcs11_RSA_public_decrypt(int flen,
		const unsigned char *from,
		unsigned char *to,
		RSA *rsa,
		int padding)
{
	CK_ULONG bytesDecrypted = 0;
	CK_RV rv;
	CK_MECHANISM Mechanism_rsa = {CKM_RSA_PKCS, NULL, 0};
	CK_MECHANISM *pMechanism = &Mechanism_rsa;
	CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
	struct token_session *wrapper = NULL;
	CK_SESSION_HANDLE session;

	DBG_fprintf("%s\n", __FUNCTION__);

	if (padding != RSA_PKCS1_PADDING)
	{
		PKCS11err(PKCS11_F_RSA_PUB_DEC, PKCS11_R_UNKNOWN_PADDING_TYPE);
		return -1;
	}

	session = (CK_SESSION_HANDLE)RSA_get_ex_data(rsa, pkcs11Session);
	if (session == CK_INVALID_HANDLE || !session) {
		wrapper = pkcs11_getSession();
		if (!wrapper)
			return 0;

		DBG_fprintf("%d: created new session\n", __LINE__);
		session = wrapper->session;
		RSA_set_ex_data(rsa, pkcs11Session, (void *)session);
	}

	hPublicKey = (CK_OBJECT_HANDLE)RSA_get_ex_data(rsa, rsaPubKey);
	if (hPublicKey == CK_INVALID_HANDLE)
		hPublicKey = pkcs11_FindOrCreateKey(session, rsa, CKO_PUBLIC_KEY, true);

	if (hPublicKey != CK_INVALID_HANDLE)
	{
		rv = pFunctionList->C_VerifyRecoverInit(session, pMechanism, hPublicKey);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PUB_DEC, PKCS11_R_VERIFYRECOVERINIT, rv);
			bytesDecrypted = -1;
			goto out;
		}

		rv = pFunctionList->C_VerifyRecover(session, (unsigned char *)from,
				flen, NULL_PTR, &bytesDecrypted);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PUB_DEC, PKCS11_R_VERIFYRECOVER, rv);
			bytesDecrypted = -1;
			goto out;
		}
		rv = pFunctionList->C_VerifyRecover(session, (unsigned char *)from,
				flen, to, &bytesDecrypted);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_PUB_DEC, PKCS11_R_VERIFYRECOVER, rv);
			bytesDecrypted = -1;
			goto out;
		}
	}

out:
	OPENSSL_free(wrapper);
	return bytesDecrypted;
}

static int pkcs11_RSA_init(RSA *rsa)
{
	struct token_session *wrapper;

	DBG_fprintf("%s\n", __FUNCTION__);

	wrapper = pkcs11_getSession();
	if (wrapper)
		RSA_set_ex_data(rsa, pkcs11Session, (void *)wrapper->session);

	RSA_blinding_off(rsa);

	return 1;
}

static int pkcs11_RSA_finish(RSA *rsa)
{
	CK_RV rv;
	CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;
	long deletePubKey;
	long deletePrivKey;
	struct token_session *wrapper = NULL;
	CK_SESSION_HANDLE session;
	int err = 0;

	DBG_fprintf("%s\n", __FUNCTION__);
/*
	if (rsa->_method_mod_n != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_n);
	if (rsa->_method_mod_p != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_p);
	if (rsa->_method_mod_q != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_q);
*/
	deletePrivKey = (long)RSA_get_ex_data(rsa, deletePrivKeyOnFree);
	hPrivateKey = (CK_OBJECT_HANDLE)RSA_get_ex_data(rsa, rsaPrivKey);

	session = (CK_SESSION_HANDLE)RSA_get_ex_data(rsa, pkcs11Session);
	if (session == CK_INVALID_HANDLE || !session) {
		wrapper = pkcs11_getSession();
		if (!wrapper)
			return 0;

		DBG_fprintf("%d: created new session\n", __LINE__);
		session = wrapper->session;
	}

	if ((deletePrivKey) && (hPrivateKey != CK_INVALID_HANDLE))
	{
		rv = pFunctionList->C_DestroyObject(session, hPrivateKey);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_FINISH, PKCS11_R_DESTROYOBJECT, rv);
			goto out;
		}
		hPrivateKey = CK_INVALID_HANDLE;
		RSA_set_ex_data(rsa, rsaPrivKey, (void *)hPrivateKey);
		deletePrivKey = FALSE;
		RSA_set_ex_data(rsa, deletePrivKeyOnFree, (void *)deletePrivKey);
	}

	deletePubKey = (long)RSA_get_ex_data(rsa, deletePubKeyOnFree);
	hPublicKey = (CK_OBJECT_HANDLE)RSA_get_ex_data(rsa, rsaPubKey);

	if ((deletePubKey) && (hPublicKey != CK_INVALID_HANDLE))
	{
		rv = pFunctionList->C_DestroyObject(session, hPublicKey);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_FINISH, PKCS11_R_DESTROYOBJECT, rv);
			goto out;
		}
		hPublicKey = CK_INVALID_HANDLE;
		RSA_set_ex_data(rsa, rsaPubKey, (void *)hPublicKey);
		deletePubKey = FALSE;
		RSA_set_ex_data(rsa, deletePubKeyOnFree, (void *)deletePubKey);
	}

	rv = pFunctionList->C_CloseSession(session);
	RSA_set_ex_data(rsa, pkcs11Session, (void *)CK_INVALID_HANDLE);
	err = 1;
out:
	OPENSSL_free(wrapper);
	return err;
}

static int pkcs11_RSA_generate_key_with_mechanism(RSA* rsa,
		CK_MECHANISM *pMechanism,
		int bits,
		BIGNUM *bn_e,
		BN_GENCB *cb,
		CK_BBOOL token)
{
	CK_ULONG i;
	CK_OBJECT_HANDLE hPublicKey;
	CK_OBJECT_HANDLE hPrivateKey;
	CK_OBJECT_CLASS oPublicKey = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS oPrivateKey = CKO_PRIVATE_KEY;
	CK_KEY_TYPE kType = CKK_RSA;
	CK_ULONG ulPublicKeyAttributeCount = 8; 
	CK_ATTRIBUTE aPublicKeyTemplate[] =
	{
		{CKA_CLASS, &oPublicKey, sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN, (void *)NULL, 0},
		{CKA_PRIVATE, &false, sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE, &false, sizeof(false)},
		{CKA_KEY_TYPE, &kType, sizeof(CK_KEY_TYPE)},
		{CKA_MODULUS_BITS, (void *)&bits, sizeof(bits)},
		{CKA_PUBLIC_EXPONENT, (void *)NULL, 0},
		{CKA_ID, PKCS11_KEY_ID, 16}
	};
	CK_ULONG	 ulPublicKeyAttributeResultCount = 2;
	CK_ATTRIBUTE aPublicKeyResult[] =
	{
		{CKA_MODULUS, (void *)NULL, 0},
		/* {CKA_MODULUS_BITS, (void *)NULL, 0}, */
		{CKA_PUBLIC_EXPONENT, (void *)NULL, 0}
	};
	CK_ULONG	ulPrivateKeyAttributeCount = 12; 
	CK_ATTRIBUTE    aPrivateKeyTemplate[] =
	{
		{CKA_CLASS, &oPrivateKey, sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN, (void *)NULL, 0},
		{CKA_PRIVATE, &false, sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE, &false, sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE, &kType, sizeof(CK_KEY_TYPE)},
		{CKA_SENSITIVE, &true, sizeof(CK_BBOOL)},
		{CKA_DECRYPT, &true, sizeof(CK_BBOOL)},
		{CKA_SIGN, &true, sizeof(CK_BBOOL)},
		{CKA_SIGN_RECOVER, &true, sizeof(CK_BBOOL)},
		{CKA_UNWRAP, &true, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &true, sizeof(CK_BBOOL)},
		{CKA_ID, PKCS11_KEY_ID, 16}
	};
	CK_RV rv;
	CK_ATTRIBUTE *pModulus = NULL;
	CK_ATTRIBUTE *pExponent = NULL;
	int ret = 1;
	struct token_session *wrapper = NULL;
	CK_SESSION_HANDLE session;
#ifndef OLDER_OPENSSL
	BIGNUM *n;
#endif

	DBG_fprintf("%s\n", __FUNCTION__);

	aPublicKeyTemplate[6].ulValueLen = BN_num_bytes(bn_e);
	aPublicKeyTemplate[6].pValue = OPENSSL_malloc(aPublicKeyTemplate[6].ulValueLen);
	i = BN_bn2bin(bn_e, aPublicKeyTemplate[6].pValue);
	aPublicKeyTemplate[1].ulValueLen = sizeof(token);
	aPublicKeyTemplate[1].pValue = &token;
	aPrivateKeyTemplate[1].ulValueLen = sizeof(token);
	aPrivateKeyTemplate[1].pValue = &token;

	session = (CK_SESSION_HANDLE)RSA_get_ex_data(rsa, pkcs11Session);
	if (session == CK_INVALID_HANDLE || !session) {
		wrapper = pkcs11_getSession();
		if (!wrapper)
			return 0;

		DBG_fprintf("%d: created new session\n", __LINE__);
		session = wrapper->session;
		RSA_set_ex_data(rsa, pkcs11Session, (void *)session);
	}

	rv = pFunctionList->C_GenerateKeyPair(session,
			pMechanism,
			aPublicKeyTemplate,
			ulPublicKeyAttributeCount,
			aPrivateKeyTemplate,
			ulPrivateKeyAttributeCount,
			&hPublicKey,
			&hPrivateKey);
	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_RSA_GEN_KEY, PKCS11_R_GEN_KEY, rv);
		ret = 0;
		goto err;
	}

	rv = pFunctionList->C_GetAttributeValue(session, hPublicKey, aPublicKeyResult, ulPublicKeyAttributeResultCount);

	switch(rv) 
	{
		case CKR_OK:
			for(i = 0; i < ulPublicKeyAttributeResultCount; i++) 
			{ /* Al	locate required buffers */
				if (((CK_LONG) aPublicKeyResult[i].ulValueLen) == -1) 
				{ /* can't get this attribute */
					PKCS11err(PKCS11_F_RSA_GEN_KEY, PKCS11_R_NO_MODULUS_OR_NO_EXPONENT);
					goto err;
				}
				else 
				{
					aPublicKeyResult[i].pValue = OPENSSL_malloc(aPublicKeyResult[i].ulValueLen);
					if (!aPublicKeyResult[i].pValue)
					{
						PKCS11err(PKCS11_F_RSA_GEN_KEY, PKCS11_R_GEN_KEY);
						goto err;
					}
				}
			}
			break;
		case CKR_ATTRIBUTE_SENSITIVE:
		case CKR_ATTRIBUTE_TYPE_INVALID:
			PKCS11err(PKCS11_F_RSA_GEN_KEY, PKCS11_R_ATTRIBUT_SENSITIVE_OR_INVALID);
			goto err;
		default:
			PKCS11err(PKCS11_F_RSA_GEN_KEY, PKCS11_R_GETATTRIBUTVALUE);
			goto err;
	}
	/*	 Then get the values */
	rv = pFunctionList->C_GetAttributeValue(session, hPublicKey, aPublicKeyResult,ulPublicKeyAttributeResultCount);
	switch(rv) 
	{
		case CKR_OK:
			break;
		case CKR_ATTRIBUTE_SENSITIVE:
		case CKR_ATTRIBUTE_TYPE_INVALID:
			PKCS11err(PKCS11_F_RSA_GEN_KEY, PKCS11_R_ATTRIBUT_SENSITIVE_OR_INVALID);
			goto err;
		default:
			PKCS11err(PKCS11_F_RSA_GEN_KEY, PKCS11_R_GETATTRIBUTVALUE);
			goto err;
	}

	/* recherche du Modulus */ 
	for(i = 0; i < ulPublicKeyAttributeResultCount; i++) 
	{
		if (aPublicKeyResult[i].type == CKA_MODULUS)
		{
			if (((CK_LONG) aPublicKeyResult[i].ulValueLen) != -1) 
			{
				pModulus = &(aPublicKeyResult[i]);
			}
			break;
		}
	}
	if (pModulus == NULL)
	{
		PKCS11err(PKCS11_F_RSA_GEN_KEY, PKCS11_R_NO_MODULUS);
		goto err;
	}

#ifdef OLDER_OPENSSL
	/* 	set n */ 
	rsa->n = BN_bin2bn(pModulus->pValue, pModulus->ulValueLen, rsa->n);
#else
	n = BN_new();
	BN_bin2bn(pModulus->pValue, pModulus->ulValueLen, n);
	RSA_set0_key(rsa, n, NULL, NULL);
#endif

	/*	 search Exponent */
	for(i = 0; i < ulPublicKeyAttributeResultCount; i++) 
	{
		if (aPublicKeyResult[i].type == CKA_PUBLIC_EXPONENT)
		{
			if (((CK_LONG) aPublicKeyResult[i].ulValueLen) != -1) 
			{
				pExponent = &(aPublicKeyResult[i]);
			}
			break;
		}
	}
	if (pExponent == NULL)
	{
		PKCS11err(PKCS11_F_RSA_GEN_KEY, PKCS11_R_NO_EXPONENT);
		goto err;
	}
#ifdef OLDER_OPENSSL
	/* 	set e */ 
	rsa->e = bn_e;
#else
	RSA_set0_key(rsa, NULL, bn_e, NULL);
#endif
	bn_e = NULL;

	RSA_set_ex_data(rsa, rsaPubKey, (char *)hPublicKey);
	RSA_set_ex_data(rsa, rsaPrivKey, (char *)hPrivateKey);

err:
	for(i = 0; i < ulPublicKeyAttributeResultCount; i++) 
	{
		if (aPublicKeyResult[i].pValue)
		{ 
			OPENSSL_free(aPublicKeyResult[i].pValue);
			aPublicKeyResult[i].pValue = NULL;
		}
	}
	if (aPublicKeyTemplate[6].pValue != NULL)
	{
		OPENSSL_free(aPublicKeyTemplate[6].pValue);
		aPublicKeyTemplate[6].pValue = NULL;
	}

	OPENSSL_free(wrapper);

	return ret;
}

/* ************************************************************ */
/*								*/
/*	function :	pkcs11_RSA_generate_key		*/
/*								*/
/* ************************************************************ */
static int pkcs11_RSA_generate_key(RSA* rsa,
		int bits,
		BIGNUM *bn_e,
		BN_GENCB *cb
		)
{
	CK_MECHANISM Mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_BBOOL token = TRUE;

	return pkcs11_RSA_generate_key_with_mechanism(rsa, &Mechanism, bits, bn_e, cb, token);
}

/* The private is found from the public key stored in PEM format in "pubkey_file" */
static EVP_PKEY *pkcs11_load_privkey(ENGINE* e, const char* pubkey_file,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pkey=NULL;
	FILE *pubkey;
	CK_OBJECT_HANDLE  hPrivateKey = CK_INVALID_HANDLE;
	RSA *rsa;

	DBG_fprintf("%s\n", __FUNCTION__);

	if ((pubkey=fopen(pubkey_file,"r")) != NULL)
	{
		pkey = PEM_read_PUBKEY(pubkey, NULL, NULL, NULL);
		fclose(pubkey);
		if (pkey)
		{
			rsa = EVP_PKEY_get1_RSA(pkey);
			if (rsa)
			{
				struct token_session *wrapper = NULL;
				CK_SESSION_HANDLE session;

				session = (CK_SESSION_HANDLE)RSA_get_ex_data(rsa, pkcs11Session);
				if (session == CK_INVALID_HANDLE || !session) {
					wrapper = pkcs11_getSession();
					if (!wrapper)
						return 0;

					DBG_fprintf("%d: created new session\n", __LINE__);
					session = wrapper->session;
					RSA_set_ex_data(rsa, pkcs11Session, (void *)session);
				}

				hPrivateKey = pkcs11_FindOrCreateKey(session, rsa, CKO_PRIVATE_KEY, true);
				if (hPrivateKey == CK_INVALID_HANDLE)
				{
					EVP_PKEY_free(pkey);
					pkey = NULL;
				}
				OPENSSL_free(wrapper);
			}
			else
			{
				EVP_PKEY_free(pkey);
				pkey = NULL;
			}
		}
	}
	return(pkey);
}

static EVP_PKEY *pkcs11_load_pubkey(ENGINE* e, const char* pubkey_file,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pkey=NULL;
	FILE *pubkey;
	CK_OBJECT_HANDLE  hPublicKey = CK_INVALID_HANDLE;
	RSA *rsa;

	DBG_fprintf("%s\n", __FUNCTION__);

	if ((pubkey=fopen(pubkey_file,"r")) != NULL)
	{
		pkey = PEM_read_PUBKEY(pubkey, NULL, NULL, NULL);
		fclose(pubkey);
		if (pkey)
		{
			rsa = EVP_PKEY_get1_RSA(pkey);
			if (rsa)
			{
				struct token_session *wrapper = NULL;
				CK_SESSION_HANDLE session;

				session = (CK_SESSION_HANDLE)RSA_get_ex_data(rsa, pkcs11Session);
				if (session == CK_INVALID_HANDLE || !session) {
					wrapper = pkcs11_getSession();
					if (!wrapper)
						return 0;

					DBG_fprintf("%d: created new session\n", __LINE__);
					session = wrapper->session;
					RSA_set_ex_data(rsa, pkcs11Session, (void *)session);
				}

				hPublicKey = pkcs11_FindOrCreateKey(session, rsa, CKO_PUBLIC_KEY, true);
				if (hPublicKey == CK_INVALID_HANDLE)
				{
					EVP_PKEY_free(pkey);
					pkey = NULL;
				}
				OPENSSL_free(wrapper);
			}
			else
			{
				EVP_PKEY_free(pkey);
				pkey = NULL;
			}
		}
	}
	return(pkey);
}

#endif

static void pkcs11_rand_cleanup(void)
{
	return;
}

#ifdef OLDER_OPENSSL
static void pkcs11_rand_add(const void *buf, int num, double entropy)
#else
static int pkcs11_rand_add(const void *buf, int num, double entropy)
#endif
{
	CK_RV rv;
	struct token_session *wrapper;
#ifndef OLDER_OPENSSL
	int ret = 0;
#endif

	DBG_fprintf("%s\n", __FUNCTION__);

	/* return any token */
	wrapper = pkcs11_getSession();
	if (!wrapper)
#ifdef OLDER_OPENSSL
		return;
#else
		return 0;
#endif

	rv = pFunctionList->C_SeedRandom(wrapper->session, (CK_BYTE_PTR)&entropy, sizeof(entropy));
	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_RAND_ADD, PKCS11_R_SEEDRANDOM, rv);
		goto out;
	}

	rv = pFunctionList->C_GenerateRandom(wrapper->session, (CK_BYTE *)buf, num);
	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_RAND_ADD, PKCS11_R_GENERATERANDOM, rv);
		goto out;
	}

#ifndef OLDER_OPENSSL
	ret = 1;
#endif

out:	pFunctionList->C_CloseSession(wrapper->session);
	OPENSSL_free(wrapper);

#ifndef OLDER_OPENSSL
	return ret;
#endif
}

#ifdef OLDER_OPENSSL
static void pkcs11_rand_seed(const void *buf, int num)
#else
static int pkcs11_rand_seed(const void *buf, int num)
#endif
{
	DBG_fprintf("%s\n", __FUNCTION__);

#ifdef OLDER_OPENSSL
	pkcs11_rand_add(buf, num, num);
#else
	return pkcs11_rand_add(buf, num, num);
#endif
}

static int pkcs11_rand_bytes(unsigned char *buf,
		int num)
{
	CK_RV rv;
	struct token_session *wrapper;
 
	DBG_fprintf("%s\n", __FUNCTION__);

	/* return any token */
	wrapper = pkcs11_getSession();
	if (!wrapper)
		return 0;

	rv = pFunctionList->C_GenerateRandom(wrapper->session, buf, num);
	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_RAND_BYTES, PKCS11_R_GENERATERANDOM, rv);
		pFunctionList->C_CloseSession(wrapper->session);
		OPENSSL_free(wrapper);
		return 0;
	}

	pFunctionList->C_CloseSession(wrapper->session);
	OPENSSL_free(wrapper);
	return 1;
}

static int pkcs11_rand_status(void)
{
	DBG_fprintf("%s\n", __FUNCTION__);

	return 1;
}

static int pkcs11_des_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc)
{
	return pkcs11_init_key(ctx, key, iv, enc, alg_des);
}

static int pkcs11_tdes_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc)
{
	return pkcs11_init_key(ctx, key, iv, enc, alg_tdes);
}

static int pkcs11_aes_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc)
{
	return pkcs11_init_key(ctx, key, iv, enc, alg_aes);
}

static inline int get_mech(int alg, EVP_CIPHER_CTX *ctx)
{
	switch (alg) {
		case alg_des:
			if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE)
				return CKM_DES_ECB;
			else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
				return CKM_DES_CBC;
			}
			return -1;

		case alg_tdes:
			if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE)
				return CKM_DES3_ECB;
			else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
				return CKM_DES3_CBC;
			}
			return -1;

		case alg_aes:
			if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_ECB_MODE) {
				return CKM_AES_ECB;
			} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
				return CKM_AES_CBC;
			}
			return -1;

		case alg_sha:
			return CKM_SHA_1;
		case alg_sha224:
			return CKM_SHA224;
		case alg_sha256:
			return CKM_SHA256;
		case alg_sha384:
			return CKM_SHA384;
		case alg_sha512:
			return CKM_SHA512;
		case alg_md5:
			return CKM_MD5;
		case alg_ripemd:
			return CKM_RIPEMD160;
		default:
			return -1;
	}
}

static int pkcs11_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc, int alg)
{
	int ret = 0;
	CK_RV rv;
	CK_MECHANISM_TYPE mech = get_mech(alg, ctx);
	CK_MECHANISM mechanism = { mech, NULL, 0 };
	CK_SESSION_HANDLE session;
	struct _token *token;
	struct token_session *wrapper = pkcs11_getSession();
	CK_BBOOL true = TRUE;
	CK_BBOOL boolenc;
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType;
	/* A secret key template */
	CK_ATTRIBUTE template[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_TOKEN, &true, sizeof(true)},
		{CKA_ENCRYPT, &boolenc, sizeof(boolenc)},
		{CKA_VALUE, (void *)key, EVP_CIPHER_CTX_key_length(ctx)}
	};
	
	/* and finally a cryptoki key handle */
	CK_OBJECT_HANDLE hkey;

	DBG_fprintf("%s\n", __FUNCTION__);
#ifdef OLDER_OPENSSL
	DBG_fprintf("EVP_CIPHER_CTX_mode(ctx): %lu,		\
		     EVP_CIPH_CBC_MODE: %d, iv: %p, ctx->iv: %p\n",
		    EVP_CIPHER_CTX_mode(ctx), EVP_CIPH_CBC_MODE, iv,
		    ctx->iv);
#else
	DBG_fprintf("EVP_CIPHER_CTX_mode(ctx): %lu,		\
		     EVP_CIPH_CBC_MODE: %d, iv: %p, ctx->iv: %p\n",
		    EVP_CIPHER_CTX_mode(ctx), EVP_CIPH_CBC_MODE, iv,
		    EVP_CIPHER_CTX_iv(ctx));
#endif

	if (mech==-1) {
		PKCS11err(PKCS11_F_INITKEY, PKCS11_R_BADMECHANISM);
		goto out;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
#ifdef OLDER_OPENSSL
		mechanism.pParameter = (CK_VOID_PTR)(iv ? iv : ctx->iv);
#else
		mechanism.pParameter = (CK_VOID_PTR)(iv ? iv : EVP_CIPHER_CTX_iv(ctx));
#endif
		mechanism.ulParameterLen = EVP_CIPHER_CTX_iv_length(ctx);

		if (mechanism.pParameter == NULL || mechanism.ulParameterLen == 0) {
			PKCS11err(PKCS11_F_INITKEY, PKCS11_R_BADMECHANISM);
			goto out;
		}
	}

	if (!wrapper) 
		goto out;
	
	/* Save the token number and session ID in the cipher context's
	 * private data area. The operation will have to continue on this
	 * token later.
	 */
	token = wrapper->token;
	session = wrapper->session;
	CIPHER_DATA(ctx)->token = token;
	CIPHER_DATA(ctx)->session = session;
	OPENSSL_free(wrapper);

	switch (alg) {
		case alg_des:
			keyType = CKK_DES;
			break;
		case alg_tdes:
			keyType = CKK_DES3;
			break;
		case alg_aes:
			keyType = CKK_AES;
			break;
		default:
			PKCS11err(PKCS11_F_INITKEY, PKCS11_R_UNKNOWN_ALGORITHM_TYPE);
			ERR_add_error_data(1, alg_to_string(alg));
			goto out_closesession;
			break;
	}

	boolenc = (enc ? TRUE : FALSE);

	rv = pFunctionList->C_CreateObject(session, template, 5, &hkey);
	if (rv != CKR_OK) {
		pkcs11_die(PKCS11_F_INITKEY, PKCS11_R_CREATEOBJECT, rv);
		goto out_closesession;
	}

	if (enc) {
		rv = pFunctionList->C_EncryptInit(session, &mechanism, hkey);
		if (rv != CKR_OK) {
			pkcs11_die(PKCS11_F_INITKEY, PKCS11_R_ENCRYPTINIT, rv);
			goto out_closesession;
		}
	} else {
		rv = pFunctionList->C_DecryptInit(session, &mechanism, hkey);
		if (rv != CKR_OK) {
			pkcs11_die(PKCS11_F_INITKEY, PKCS11_R_DECRYPTINIT, rv);
			goto out_closesession;
		}
	}

	ret = 1;

	goto out;

out_closesession:
	/* Execute only if we opened a session, but then failed */
	pFunctionList->C_CloseSession(session);

out:
	return ret;
}   // end pkcs11_init_key

static int
pkcs11_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
	DBG_fprintf("%s\n", __FUNCTION__);
	pFunctionList->C_CloseSession(CIPHER_DATA(ctx)->session);
	CIPHER_DATA(ctx)->session = CK_INVALID_HANDLE;
	return 1;
}

static inline int pkcs11_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
		const unsigned char *in, size_t inlen)
{
	unsigned long outlen = inlen;
	CK_RV rv;
	CK_SESSION_HANDLE session;

	DBG_fprintf("%s\n", __FUNCTION__);

	session = CIPHER_DATA(ctx)->session;

#ifdef OLDER_OPENSSL
	if (ctx->encrypt) {
#else
	if (EVP_CIPHER_CTX_encrypting(ctx)) {
#endif
		rv = pFunctionList->C_EncryptUpdate(session, (void *)in, inlen, (void *)out, &outlen);

		if (rv) {
			pkcs11_die(PKCS11_F_CIPHER_UPDATE, PKCS11_R_ENCRYPT, rv);
			return 0;
		} 
	} else {
		rv = pFunctionList->C_DecryptUpdate(session, (void *)in, inlen, (void *)out, &outlen);

		if (rv) {
			pkcs11_die(PKCS11_F_CIPHER_UPDATE, PKCS11_R_DECRYPT, rv);
			return 0;
		} 
	}

	return 1;
}

static inline int
pkcs11_sha1_init(EVP_MD_CTX *ctx)
{
	return pkcs11_digest_init(ctx, alg_sha);
}
static inline int
pkcs11_sha224_init(EVP_MD_CTX *ctx)
{
	return pkcs11_digest_init(ctx, alg_sha224);
}
static inline int
pkcs11_sha256_init(EVP_MD_CTX *ctx)
{
	return pkcs11_digest_init(ctx, alg_sha256);
}
static inline int
pkcs11_sha384_init(EVP_MD_CTX *ctx)
{
	return pkcs11_digest_init(ctx, alg_sha384);
}
static inline int
pkcs11_sha512_init(EVP_MD_CTX *ctx)
{
	return pkcs11_digest_init(ctx, alg_sha512);
}

static inline int
pkcs11_md5_init(EVP_MD_CTX *ctx)
{
	return pkcs11_digest_init(ctx, alg_md5);
}

static inline int
pkcs11_ripemd160_init(EVP_MD_CTX *ctx)
{
	return pkcs11_digest_init(ctx, alg_ripemd);
}

static inline int
pkcs11_digest_init(EVP_MD_CTX *ctx, int alg)
{
	CK_RV rv;
	struct token_session *wrapper = pkcs11_getSession();

	if (!wrapper)
		return 0;

	MD_DATA(ctx)->token = wrapper->token;
	MD_DATA(ctx)->session = wrapper->session;
	OPENSSL_free(wrapper);

	DBG_fprintf("%s, alg = %d\n", __FUNCTION__, alg);

	MD_DATA(ctx)->alg = alg;

	CK_MECHANISM_TYPE mech = get_mech(MD_DATA(ctx)->alg, NULL);
	CK_MECHANISM mechanism = {mech, NULL, 0};

	rv = pFunctionList->C_DigestInit(MD_DATA(ctx)->session, &mechanism);
	if (rv != CKR_OK) {
		DBG_fprintf("failed init\n");
		pkcs11_die(PKCS11_F_DIGESTFINISH, PKCS11_R_DIGESTINIT, rv);
		pFunctionList->C_CloseSession(MD_DATA(ctx)->session);
		return 0;
	}

	return 1;
}

static int
pkcs11_digest_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
	CK_RV rv;

	DBG_fprintf("%s, len = %lu\n", __FUNCTION__, len);

	if (!MD_DATA(ctx)) {
		PKCS11err(PKCS11_F_DIGESTUPDATE, PKCS11_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	
	rv = pFunctionList->C_DigestUpdate(MD_DATA(ctx)->session,
					   (CK_BYTE_PTR)in, len);
	if (rv != CKR_OK) {
		DBG_fprintf("failed update\n");
		pkcs11_die(PKCS11_F_DIGESTUPDATE, PKCS11_R_DIGESTUPDATE, rv);
		return 0;
	}
	
	MD_DATA(ctx)->len += len;

	return 1;
}

static int
pkcs11_digest_finish(EVP_MD_CTX *ctx, unsigned char *md)
{
	CK_ULONG len = EVP_MD_CTX_size(ctx);
	CK_RV rv;
	int ret = 0;

	DBG_fprintf("%s\n", __FUNCTION__);

	rv = pFunctionList->C_DigestFinal(MD_DATA(ctx)->session, md, &len);
	if (rv != CKR_OK) {
		DBG_fprintf("failed final\n");
		pkcs11_die(PKCS11_F_DIGESTFINISH, PKCS11_R_DIGESTFINAL, rv);
		goto out_endsession;
	}

	ret = 1;

out_endsession:
	pFunctionList->C_CloseSession(MD_DATA(ctx)->session);
	MD_DATA(ctx)->session = CK_INVALID_HANDLE;
	return ret;
}

static int
pkcs11_digest_copy(EVP_MD_CTX *dst, const EVP_MD_CTX *src)
{
	CK_RV rv;
	CK_ULONG opstatelen;
	CK_BYTE_PTR opstate;

	//if (EVP_MD_CTX_test_flags(in, EVP_MD_CTX_FLAG_NO_INIT))
	//	return 1;

	DBG_fprintf("%s\n", __FUNCTION__);

	/* pull operation state from src context */
	rv = pFunctionList->C_GetOperationState(MD_DATA(src)->session,
						NULL_PTR, &opstatelen);
	if (rv != CKR_OK) {
		DBG_fprintf("GetOperationState failed\n");
		pkcs11_die(PKCS11_F_DIGESTCOPY, PKCS11_R_DIGESTUPDATE, rv);
		return 0;
	}
	opstate = (CK_BYTE_PTR) OPENSSL_malloc(opstatelen);
	rv = pFunctionList->C_GetOperationState(MD_DATA(src)->session,
						opstate, &opstatelen);
	if (rv != CKR_OK) {
		DBG_fprintf("GetOperationState failed\n");
		pkcs11_die(PKCS11_F_DIGESTCOPY, PKCS11_R_DIGESTUPDATE, rv);
		return 0;
	}

	/* init a new session for the dst context */
	rv = pkcs11_digest_init(dst, MD_DATA(src)->alg);

	/* set the operation state pulled above for this new session  */
	rv = pFunctionList->C_SetOperationState(MD_DATA(dst)->session, opstate,
						opstatelen, 0, 0);
	if (rv != CKR_OK) {
		DBG_fprintf("SetOperationState failed\n");
		pkcs11_die(PKCS11_F_DIGESTCOPY, PKCS11_R_DIGESTUPDATE, rv);
		return 0;
	}

	OPENSSL_free(opstate);

	return 1;
}

static inline int
pkcs11_digest_cleanup(EVP_MD_CTX *ctx)
{
	return 1;
}

void pkcs11_engine_destructor(void) __attribute__((destructor));
/* the destructor handles the case where openssl called bind_pkcs11, which calls pre_init_pkcs11,
 * which then found some PCKS#11 slots and called pkcs11_addToken, but then openssl decided not
 * to use us */
void pkcs11_engine_destructor(void)
{
	struct _token *tmp;

	while (pkcs11_token_list) {
		tmp = pkcs11_token_list->token_next;
		OPENSSL_free(pkcs11_token_list);
		pkcs11_token_list = tmp;
	}
}

#endif
#endif

