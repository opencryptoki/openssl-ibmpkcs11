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

#include <openssl/e_os2.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/engine.h>
#include <openssl/dso.h>
#include <openssl/err.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <pthread.h>

#ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_PKCS11



#include "cryptoki.h"
#include "e_pkcs11_err.h"
#include "e_pkcs11.h"
/* SHA224, CAMELLIA */
#include "pkcs-11v2-20a3.h"

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
static int pkcs11_RSA_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, const RSA *rsa);

/* this API changed in OpenSSL version 1.0.0 */
#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
static int pkcs11_RSA_verify(int dtype, const unsigned char *m, unsigned int m_len,
		unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);
#else
static int pkcs11_RSA_verify(int dtype, const unsigned char *m, unsigned int m_len,
		const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);
#endif

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
static void pkcs11_rand_seed(const void *buf, int num);
static void pkcs11_rand_add(const void *buf, int num, double add_entropy);
static void pkcs11_rand_cleanup(void);
static int pkcs11_rand_bytes(unsigned char *buf, int num);
static int pkcs11_rand_status(void);

/* cipher function prototypes */
static inline int pkcs11_init_key(EVP_CIPHER_CTX * ctx, const unsigned char *key,
		const unsigned char *iv, int enc, int alg);
static inline int pkcs11_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
		const unsigned char *in, unsigned int inlen);
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
static inline int pkcs11_ripemd_init(EVP_MD_CTX *ctx);
/* End digest function prototypes */

static int pre_init_pkcs11(ENGINE *e);
static int pkcs11_engine_ciphers(ENGINE * e, const EVP_CIPHER ** cipher,
		const int **nids, int nid);
static int pkcs11_engine_digests(ENGINE * e, const EVP_MD ** digest,
		const int **nids, int nid);


/* Number of NID's that exist in OpenSSL 1.0.0a */
#define NUM_NID 893
int pkcs11_implemented_ciphers[NUM_NID] = { 0, };
int pkcs11_implemented_digests[NUM_NID] = { 0, };
pid_t mypid = -1;

/* The definitions for control commands specific to this engine */
#define PKCS11_CMD_SO_PATH		ENGINE_CMD_BASE
#define PKCS11_CMD_USER_PIN             (ENGINE_CMD_BASE+1)
static const ENGINE_CMD_DEFN pkcs11_cmd_defns[] =
{
	{ PKCS11_CMD_SO_PATH,
		"SO_PATH",
		"Specifies the path to the 'pkcs#11' shared library",
		ENGINE_CMD_FLAG_STRING
	},
	{ PKCS11_CMD_USER_PIN,
		"USER_PIN",
		"Provides the user PIN for devices that need one to function",
		ENGINE_CMD_FLAG_STRING
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
 *    struct, digest_update to append data to the data field within
 *    that struct, finalize() to call C_Digest() on all the data
 *    at once, and cleanup() to free the context struct.
 *   The digest approach is part of the openbsd implementation.  We
 *    do not do anything about the potential EVP_MD_FLAG_ONESHOT
 *    condition in update(), because openssl will still call finalize
 *    after that.
 */

/* 
 * Each cipher/digest action requires a new session.  We store the
 * session and its token in the context->cipher_data void* using
 * this struct
 */
struct token_session {
	struct _token *token;
	CK_SESSION_HANDLE session;
};

/*
 * For digests:
 * We follow the example of openbsd_hw.c: digest_update just builds up
 * an array of what to process.  final() runs the digest on that data.
 * TODO: In order to prevent memory problems when we have a huge input,
 * we may want to trigger a do_digest when len gets too big.
 */
#define PKCS11_DIGEST_BLOCK_SIZE 4096
struct pkcs11_digest_ctx {
	int alg;
	char *data;
	int len;
	int size; /* alloc'd size of data so far */
	int *ref_cnt; /* number of references to this digest operation */
};

/********/

#define CIPHER_DATA(ctx) ((struct token_session *)(ctx->cipher_data))
#define MD_DATA(ctx) ((struct token_session *)(ctx->md_data))

static int num_cipher_nids = 0;
static int num_digest_nids = 0;

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
	24,			/* Block size */
	24,			/* Key len */
	24,			/* IV len */
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
	32,			/* Block size */
	32,			/* Key len */
	32,			/* IV len */
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
	24,			/* Block size */
	24,			/* Key len */
	24,			/* IV len */
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
	32,			/* Block size */
	32,			/* Key len */
	32,			/* IV len */
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

/* Message Digests */
const EVP_MD pkcs11_sha1 = {
       NID_sha1,
       NID_sha1WithRSAEncryption,
       SHA_DIGEST_LENGTH,
       0,
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
       0,
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
       0,
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
       0,
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
       0,
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

const EVP_MD pkcs11_ripemd = {
       NID_ripemd160,
       NID_ripemd160WithRSA,
       RIPEMD160_DIGEST_LENGTH,
       0, /* flags */
       pkcs11_ripemd_init,
       pkcs11_digest_update,
       pkcs11_digest_finish,  /* final */
       pkcs11_digest_copy,
       pkcs11_digest_cleanup,  /* cleanup */
       EVP_PKEY_RSA_method,
       RIPEMD160_CBLOCK,
       sizeof(struct pkcs11_digest_ctx)
};

/********/


#ifndef OPENSSL_NO_RSA
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
	pkcs11_RSA_sign,                               /* rsa_sign */
	pkcs11_RSA_verify,                             /* rsa_verify */
	pkcs11_RSA_generate_key                       /* rsa_generate_key */ 
};

RSA_METHOD *PKCS11_RSA(void)
{
	return(&pkcs11_rsa);
}
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
/* OPENCRYPTOKI is the default, specified on the command line as part of the build */
static char *def_PKCS11_LIBNAME = sizeof(long) == 8 ?
"/usr/lib64/pkcs11/PKCS11_API.so":
"/usr/lib/pkcs11/PKCS11_API.so";
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
	struct token_session *wrapper = OPENSSL_malloc(sizeof (struct token_session));

	if (!wrapper) {
		PKCS11err(PKCS11_F_GETSESSION, PKCS11_R_MALLOC_FAILURE);
		return NULL;
	}

	wrapper->token = pkcs11_token_list;

	if (!PKCS11_Initialized) {
		rv = pFunctionList->C_Initialize(NULL);
		if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			pkcs11_die(PKCS11_F_GETSESSION, PKCS11_R_INITIALIZE, rv);
			return NULL;
		}
		PKCS11_Initialized = 1;
	}

	rv = pFunctionList->C_OpenSession(wrapper->token->slot,
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
#if 0
	    /* RSA functions are set below, in pre_init_pkcs11(), but only
	     * when some token's mechanism list reports supporting RSA  */
#ifndef OPENSSL_NO_RSA
	    !ENGINE_set_RSA(e, &pkcs11_rsa) ||
	    !ENGINE_set_load_privkey_function(e, pkcs11_load_privkey) ||
	    !ENGINE_set_load_pubkey_function(e, pkcs11_load_pubkey) ||
#endif
#endif
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
	int i, count = 0;

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
	int i, count = 0;

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

	/* If the algorithm requested was not added to the list at
	 * engine init time, don't return a reference to that structure.
	 */
	if (pkcs11_implemented_ciphers[nid]) {
		switch (nid) {
			case NID_aes_128_ecb:
				*cipher = &pkcs11_aes_128_ecb;
				break;
			case NID_aes_192_ecb:
				*cipher = &pkcs11_aes_192_ecb;
				break;
			case NID_aes_256_ecb:
				*cipher = &pkcs11_aes_256_ecb;
				break;
			case NID_aes_128_cbc:
				*cipher = &pkcs11_aes_128_cbc;
				break;
			case NID_aes_192_cbc:
				*cipher = &pkcs11_aes_192_cbc;
				break;
			case NID_aes_256_cbc:
				*cipher = &pkcs11_aes_256_cbc;
				break;
			case NID_des_ecb:
				*cipher = &pkcs11_des_ecb;
				break;
			case NID_des_cbc:
				*cipher = &pkcs11_des_cbc;
				break;
			case NID_des_ede3_ecb:
				*cipher = &pkcs11_tdes_ecb;
				break;
			case NID_des_ede3_cbc:
				*cipher = &pkcs11_tdes_cbc;
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

	if (pkcs11_implemented_digests[nid]) {
		switch (nid) {
			case NID_ripemd160:
				*digest = &pkcs11_ripemd;
				break;
			case NID_md5:
				*digest = &pkcs11_md5;
				break;
			case NID_sha1:
				*digest = &pkcs11_sha1;
				break;
			default:
				*digest = NULL;
				break;
		}
	}
	return (*digest != NULL);
}

/* This is a process-global DSO handle used for loading and unloading
 * the PKCS#11 library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */
static DSO *pkcs11_dso = NULL;

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

int add_hw_token(struct _token *new_tok, CK_MECHANISM_TYPE mech, struct _token **list_head,
		short *enabled, struct _token **next_ptr)
{
	CK_RV rv;
	CK_MECHANISM_INFO mech_info;

	rv = pFunctionList->C_GetMechanismInfo(new_tok->slot, mech, &mech_info);
	if (rv != CKR_OK) {
		pkcs11_die(PKCS11_F_ADDTOKEN, PKCS11_R_GETMECHANISMINFO, rv);
	}

	/* return 0 if not HW enabled */
	if ((mech_info.flags & CKF_HW) == 0)
		return 0;

	if (!*enabled) {
		*enabled = 1;
		*next_ptr = *list_head;
		*list_head = new_tok;
	}

	/* return 1 if HW enabled */
	return 1;
}

/* Add new NID's based on this slot's token */
void pkcs11_regToken(ENGINE *e, CK_SLOT_ID slot_id)
{
	CK_RV rv;
	CK_ULONG mech_cnt;
	CK_MECHANISM_TYPE_PTR mech_list;
	int i;

	DBG_fprintf("%s\n", __FUNCTION__);

	rv = pFunctionList->C_GetMechanismList(slot_id, NULL_PTR, &mech_cnt);
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

	rv = pFunctionList->C_GetMechanismList(slot_id, mech_list, &mech_cnt);
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
				ENGINE_set_RSA(e, &pkcs11_rsa);
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
				pkcs11_implemented_ciphers[NID_des_ecb] = 1;
				num_cipher_nids++;
				break;
			case CKM_DES_CBC:
			case CKM_DES_CBC_PAD:
				pkcs11_implemented_ciphers[NID_des_cbc] = 1;
				num_cipher_nids++;
				break;
			case CKM_DES_KEY_GEN:
			case CKM_DES_MAC:
			case CKM_DES_MAC_GENERAL:
				break; 
			case CKM_DES3_ECB:
				pkcs11_implemented_ciphers[NID_des_ede3_ecb] = 1;
				num_cipher_nids++;
				break;
			case CKM_DES3_CBC:
			case CKM_DES3_CBC_PAD:
				pkcs11_implemented_ciphers[NID_des_ede3_cbc] = 1;
				num_cipher_nids++;
				break;
			case CKM_DES3_KEY_GEN:
			case CKM_DES3_MAC:
			case CKM_DES3_MAC_GENERAL:
				break; 
			case CKM_SHA_1:
				pkcs11_implemented_digests[NID_sha1] = 1;
				num_digest_nids++;
				break;
			case CKM_SHA_1_HMAC:
			case CKM_SHA_1_HMAC_GENERAL:
				pkcs11_implemented_digests[NID_hmacWithSHA1] = 1;
				num_digest_nids++;
				break;
			case CKM_PBA_SHA1_WITH_SHA1_HMAC:
			case CKM_SHA1_KEY_DERIVATION:
			case CKM_SHA1_RSA_PKCS:
				pkcs11_implemented_digests[NID_sha1WithRSAEncryption] = 1;
				num_digest_nids++;
				break; 
				
			case CKM_SHA224:
				pkcs11_implemented_digests[NID_sha224] = 1;
				num_digest_nids++;
				break;
			case CKM_SHA224_KEY_DERIVATION:
			case CKM_SHA224_RSA_PKCS:
				pkcs11_implemented_digests[NID_sha224WithRSAEncryption] = 1;
				num_digest_nids++;
				break; 
				
				
			case CKM_SHA256:
				pkcs11_implemented_digests[NID_sha256] = 1;
				num_digest_nids++;
				break;
			case CKM_SHA256_KEY_DERIVATION:
			case CKM_SHA256_RSA_PKCS:
				pkcs11_implemented_digests[NID_sha256WithRSAEncryption] = 1;
				num_digest_nids++;
				break; 
				
			case CKM_SHA384:
				pkcs11_implemented_digests[NID_sha384] = 1;
				num_digest_nids++;
				break;
			case CKM_SHA384_KEY_DERIVATION:
			case CKM_SHA384_RSA_PKCS:
				pkcs11_implemented_digests[NID_sha384WithRSAEncryption] = 1;
				num_digest_nids++;
				break; 
			case CKM_SHA512:
				pkcs11_implemented_digests[NID_sha512] = 1;
				num_digest_nids++;
				break;
			case CKM_SHA512_KEY_DERIVATION:
			case CKM_SHA512_RSA_PKCS:
				pkcs11_implemented_digests[NID_sha512WithRSAEncryption] = 1;
				num_digest_nids++;
				break; 
				
			case CKM_AES_ECB:
				pkcs11_implemented_ciphers[NID_aes_128_ecb] = 1;
				pkcs11_implemented_ciphers[NID_aes_192_ecb] = 1;
				pkcs11_implemented_ciphers[NID_aes_256_ecb] = 1;
				num_cipher_nids += 3;
				break;
			case CKM_AES_KEY_GEN:
				break;
			case CKM_AES_CBC_PAD:
			case CKM_AES_CBC:
				pkcs11_implemented_ciphers[NID_aes_128_cbc] = 1;
				pkcs11_implemented_ciphers[NID_aes_192_cbc] = 1;
				pkcs11_implemented_ciphers[NID_aes_256_cbc] = 1;
				num_cipher_nids += 3;
				break;
			case CKM_AES_MAC:
			case CKM_AES_MAC_GENERAL:
				break; 
			case CKM_MD5:
				pkcs11_implemented_digests[NID_md5] = 1;
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
				pkcs11_implemented_digests[NID_ripemd160] = 1;
				num_digest_nids++;
				break;
			case CKM_RIPEMD160_HMAC:
			case CKM_RIPEMD160_HMAC_GENERAL:
				break;
			default:
				DBG_fprintf("The token in slot %lx has reported that it can "
					    "perform\nmechanism 0x%lx, which is not available to "
					    "accelerate in openssl.\n", slot_id, mech_list[i]);
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
void pkcs11_addToken(CK_SLOT_ID slot_id)
{
	struct _token *new_tok = (struct _token *) OPENSSL_malloc(sizeof(struct _token));

	if (new_tok == NULL) {
		PKCS11err(PKCS11_F_ADDTOKEN, PKCS11_R_MALLOC_FAILURE);
		return;
	}

	memset(new_tok, 0, sizeof(struct _token));
	new_tok->slot = slot_id;

	new_tok->token_next = pkcs11_token_list;
	pkcs11_token_list = new_tok;
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
	int i;

	if(pkcs11_dso)
	{
		PKCS11err(PKCS11_F_PREINIT, PKCS11_R_ALREADY_LOADED);
		goto err;
	}

	/* Attempt to load PKCS#11 library */
	pkcs11_dso = DSO_load(NULL, get_PKCS11_LIBNAME(), NULL, 0);

	if(pkcs11_dso == NULL)
	{
		PKCS11err(PKCS11_F_PREINIT, PKCS11_R_DSO_FAILURE);
		goto err;
	}

	/* get the C_GetFunctionList function from the loaded library */
	p = (CK_C_GetFunctionList)DSO_bind_func(pkcs11_dso, PKCS11_GET_FUNCTION_LIST);
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
						pkcs11_die(PKCS11_F_PREINIT, PKCS11_R_GETSLOTINFO, rv);
						OPENSSL_free(pSlotList);
						goto err;
					}

					pkcs11_regToken(e, pSlotList[i]);
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
	DSO_free(pkcs11_dso);
	pkcs11_dso = NULL;

	return 1;

err:
	if(pkcs11_dso)
		DSO_free(pkcs11_dso);
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
	pkcs11_dso = DSO_load(NULL, get_PKCS11_LIBNAME(), NULL, 0);

	if(pkcs11_dso == NULL)
	{
		PKCS11err(PKCS11_F_INIT, PKCS11_R_DSO_FAILURE);
		goto err;
	}

	/* get the C_GetFunctionList function from the loaded library */
	p = (CK_C_GetFunctionList)DSO_bind_func(pkcs11_dso, PKCS11_GET_FUNCTION_LIST);
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
#endif

	if (pkcs11_token_list == NULL)
		PKCS11err(PKCS11_F_INIT, PKCS11_R_NOTOKENS);

	PKCS11_Initialized = 1;

	/* TODO:  This should only be done on linux systems */
	pthread_atfork(NULL, NULL, (void(*)())pkcs11_atfork_init);

	return 1;

err:
	if(pkcs11_dso)
		DSO_free(pkcs11_dso);
	pkcs11_dso = NULL;
	return 0;
}

/* Destructor (complements the "ENGINE_pkcs11()" constructor) */
/* XXX HUH?  Can we just DSO_load once, then??? */
static int pkcs11_destroy(ENGINE *e)
{
	DBG_fprintf("%s: called\n", __FUNCTION__);
	fflush(stderr);
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

	if(!DSO_free(pkcs11_dso))
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
	int ret=0;
	CK_ULONG Matches;
	CK_KEY_TYPE kType = CKK_RSA;
	CK_ULONG ulKeyAttributeCount;
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
		pubKeyTemplate[2].ulValueLen = BN_num_bytes(rsa->n);
		pubKeyTemplate[2].pValue = (CK_VOID_PTR)OPENSSL_malloc((size_t)pubKeyTemplate[2].ulValueLen);
		ret = BN_bn2bin(rsa->n, pubKeyTemplate[2].pValue);

		pubKeyTemplate[3].ulValueLen = BN_num_bytes(rsa->e);
		pubKeyTemplate[3].pValue = (CK_VOID_PTR)OPENSSL_malloc((size_t)pubKeyTemplate[3].ulValueLen);
		ret = BN_bn2bin(rsa->e, pubKeyTemplate[3].pValue);

		ulKeyAttributeCount = 4;
		rv = pFunctionList->C_FindObjectsInit(h, pubKeyTemplate, ulKeyAttributeCount);
	} else {
		DBG_fprintf("looking up a private key\n");
		privKeyTemplate[2].ulValueLen = BN_num_bytes(rsa->n);
		privKeyTemplate[2].pValue = (CK_VOID_PTR)OPENSSL_malloc((size_t)privKeyTemplate[2].ulValueLen);
		ret = BN_bn2bin(rsa->n, privKeyTemplate[2].pValue);

		privKeyTemplate[3].ulValueLen = BN_num_bytes(rsa->e);
		privKeyTemplate[3].pValue = (CK_VOID_PTR)OPENSSL_malloc((size_t)privKeyTemplate[3].ulValueLen);
		ret = BN_bn2bin(rsa->e, privKeyTemplate[3].pValue);

		privKeyTemplate[4].ulValueLen = BN_num_bytes(rsa->d);
		privKeyTemplate[4].pValue = (CK_VOID_PTR)OPENSSL_malloc((size_t)privKeyTemplate[4].ulValueLen);
		ret = BN_bn2bin(rsa->d, privKeyTemplate[4].pValue);

		privKeyTemplate[5].ulValueLen = BN_num_bytes(rsa->p);
		privKeyTemplate[5].pValue = (CK_VOID_PTR)OPENSSL_malloc((size_t)privKeyTemplate[5].ulValueLen);
		ret = BN_bn2bin(rsa->p, privKeyTemplate[5].pValue);

		privKeyTemplate[6].ulValueLen = BN_num_bytes(rsa->q);
		privKeyTemplate[6].pValue = (CK_VOID_PTR)OPENSSL_malloc((size_t)privKeyTemplate[6].ulValueLen);
		ret = BN_bn2bin(rsa->q, privKeyTemplate[6].pValue);

		privKeyTemplate[7].ulValueLen = BN_num_bytes(rsa->dmp1);
		privKeyTemplate[7].pValue = (CK_VOID_PTR)OPENSSL_malloc((size_t)privKeyTemplate[7].ulValueLen);
		ret = BN_bn2bin(rsa->dmp1, privKeyTemplate[7].pValue);

		privKeyTemplate[8].ulValueLen = BN_num_bytes(rsa->dmq1);
		privKeyTemplate[8].pValue = (CK_VOID_PTR)OPENSSL_malloc((size_t)privKeyTemplate[8].ulValueLen);
		ret = BN_bn2bin(rsa->dmq1, privKeyTemplate[8].pValue);

		privKeyTemplate[9].ulValueLen = BN_num_bytes(rsa->iqmp);
		privKeyTemplate[9].pValue = (CK_VOID_PTR)OPENSSL_malloc((size_t)privKeyTemplate[9].ulValueLen);
		ret = BN_bn2bin(rsa->iqmp, privKeyTemplate[9].pValue);

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
		DBG_fprintf("rsa->n is %d bytes\n", BN_num_bytes(rsa->n));
		if (fKeyCreate && BN_num_bytes(rsa->n)) {
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

	wrapper = pkcs11_getSession();
	if (!wrapper)
		return 0;
	session = wrapper->session;

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

	wrapper = pkcs11_getSession();
	if (!wrapper)
		return 0;
	session = wrapper->session;

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

	wrapper = pkcs11_getSession();
	if (!wrapper)
		return 0;
	session = wrapper->session;

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

	wrapper = pkcs11_getSession();
	if (!wrapper)
		return 0;
	session = wrapper->session;

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
	DBG_fprintf("%s\n", __FUNCTION__);
	rsa->flags |=  RSA_FLAG_SIGN_VER;
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

	if (rsa->_method_mod_n != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_n);
	if (rsa->_method_mod_p != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_p);
	if (rsa->_method_mod_q != NULL)
		BN_MONT_CTX_free(rsa->_method_mod_q);

	deletePrivKey = (long)RSA_get_ex_data(rsa, deletePrivKeyOnFree);
	hPrivateKey = (CK_OBJECT_HANDLE)RSA_get_ex_data(rsa, rsaPrivKey);

	wrapper = pkcs11_getSession();
	if (!wrapper)
		return 0;
	session = wrapper->session;

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
	err = 1;
out:
	OPENSSL_free(wrapper);
	return err;
}

static int pkcs11_RSA_sign(int type,
		const unsigned char *m,
		unsigned int m_len,
		unsigned char *sigret,
		unsigned int *siglen,
		const RSA *rsa)
{
	X509_SIG sig;
	ASN1_TYPE parameter;
	int i,j;
	unsigned char *p,*s = NULL;
	X509_ALGOR algor;
	ASN1_OCTET_STRING digest;
	CK_RV rv;
	CK_MECHANISM Mechanism_rsa = {CKM_RSA_PKCS, NULL, 0};
	CK_MECHANISM *pMechanism = &Mechanism_rsa;
	CK_OBJECT_HANDLE hPrivateKey;
	int ret = 0;
	struct token_session *wrapper = NULL;
	CK_SESSION_HANDLE session;
	CK_ULONG ulSigLen;

	DBG_fprintf("%s\n", __FUNCTION__);
	DBG_fprintf("rsa->n is %d bytes.\n", BN_num_bytes(rsa->n));

	/* Encode the digest	*/
	/* Special case: SSL signature, just check the length */
	if(type == NID_md5_sha1)
	{
		if(m_len != SSL_SIG_LENGTH)
		{
			PKCS11err(PKCS11_F_RSA_SIGN, PKCS11_R_INVALID_MESSAGE_LENGTH);
			DBG_fprintf("mlen = %d\n", m_len);
			return 0;
		}
		i = SSL_SIG_LENGTH;
		s = (unsigned char *)m;
	}
	else
	{
		sig.algor= &algor;
		sig.algor->algorithm=OBJ_nid2obj(type);
		if (sig.algor->algorithm == NULL)
		{
			PKCS11err(PKCS11_F_RSA_SIGN, PKCS11_R_UNKNOWN_ALGORITHM_TYPE);
			return 0;
		}
		if (sig.algor->algorithm->length == 0)
		{
			PKCS11err(PKCS11_F_RSA_SIGN, PKCS11_R_UNKNOWN_ASN1_OBJECT_ID);
			return 0;
		}
		parameter.type=V_ASN1_NULL;
		parameter.value.ptr=NULL;
		sig.algor->parameter= &parameter;

		sig.digest= &digest;
		sig.digest->data=(unsigned char *)m;
		sig.digest->length=m_len;

		i=i2d_X509_SIG(&sig,NULL);
	}

	j=RSA_size(rsa);
	if ((i-RSA_PKCS1_PADDING) > j)
	{
		PKCS11err(PKCS11_F_RSA_SIGN, PKCS11_R_DIGEST_TOO_BIG);
		return 0;
	}

	if(type != NID_md5_sha1)
	{
		s=(unsigned char *)OPENSSL_malloc((unsigned int)j+1);
		if (s == NULL)
		{
			PKCS11err(PKCS11_F_RSA_SIGN, PKCS11_R_MALLOC_FAILURE);
			return 0;
		}
		p=s;
		i2d_X509_SIG(&sig,&p);
	}

	wrapper = pkcs11_getSession();
	if (!wrapper)
		return 0;
	session = wrapper->session;

	hPrivateKey = (CK_OBJECT_HANDLE)RSA_get_ex_data(rsa, rsaPrivKey);
	if (hPrivateKey == CK_INVALID_HANDLE)
		hPrivateKey = pkcs11_FindOrCreateKey(session, (RSA *)rsa, CKO_PRIVATE_KEY, true);

	if (hPrivateKey != CK_INVALID_HANDLE)
	{
		rv = pFunctionList->C_SignInit(session, pMechanism, hPrivateKey);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_SIGN, PKCS11_R_SIGNINIT, rv);
			goto err;
		}

		ulSigLen = j;
		rv = pFunctionList->C_Sign(session, s, i, sigret, &ulSigLen);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_SIGN, PKCS11_R_SIGN, rv);
			goto err;
		}
		*siglen = (unsigned int)ulSigLen;
		ret = 1;
	}

	DBG_fprintf("returning *siglen = %u\n", *siglen);

err:
	if(type != NID_md5_sha1)
	{
		memset(s,0,(unsigned int)j+1);
		OPENSSL_free(s);
	}

	OPENSSL_free(wrapper);

	return ret;
}

#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
static int pkcs11_RSA_verify(int type,
		const unsigned char *m,
		unsigned int m_len,
		unsigned char *sigbuf,
		unsigned int siglen,
		const RSA *rsa)
#else
static int pkcs11_RSA_verify(int type,
		const unsigned char *m,
		unsigned int m_len,
		const unsigned char *sigbuf,
		unsigned int siglen,
		const RSA *rsa)
#endif
{
	X509_SIG sig;
	ASN1_TYPE parameter;
	int i,j;
	unsigned char *p,*s = NULL;
	X509_ALGOR algor;
	ASN1_OCTET_STRING digest;
	CK_RV rv;
	CK_MECHANISM Mechanism_rsa = {CKM_RSA_PKCS, NULL, 0};
	CK_MECHANISM *pMechanism = &Mechanism_rsa;
	CK_OBJECT_HANDLE hPublicKey;
	CK_ULONG ulSigLen;
	int ret = 0;
	struct token_session *wrapper = NULL;
	CK_SESSION_HANDLE session;

	DBG_fprintf("%s\n", __FUNCTION__);

	/* Encode the digest	*/
	/* Special case: SSL signature, just check the length */
	if(type == NID_md5_sha1)
	{
		if(m_len != SSL_SIG_LENGTH)
		{
			PKCS11err(PKCS11_F_RSA_VERIFY, PKCS11_R_INVALID_MESSAGE_LENGTH);
			DBG_fprintf("m_len = %d\n", m_len);
			return 0;
		}
		i = SSL_SIG_LENGTH;
		s = (unsigned char *)m;
	}
	else
	{
		sig.algor= &algor;
		sig.algor->algorithm=OBJ_nid2obj(type);
		if (sig.algor->algorithm == NULL)
		{
			PKCS11err(PKCS11_F_RSA_VERIFY, PKCS11_R_UNKNOWN_ALGORITHM_TYPE);
			return 0;
		}
		if (sig.algor->algorithm->length == 0)
		{
			PKCS11err(PKCS11_F_RSA_VERIFY, PKCS11_R_UNKNOWN_ASN1_OBJECT_ID);
			return 0;
		}
		parameter.type=V_ASN1_NULL;
		parameter.value.ptr=NULL;
		sig.algor->parameter= &parameter;
		sig.digest= &digest;
		sig.digest->data=(unsigned char *)m;
		sig.digest->length=m_len;
		i=i2d_X509_SIG(&sig,NULL);
	}

	j=RSA_size(rsa);
	if ((i-RSA_PKCS1_PADDING) > j)
	{
		PKCS11err(PKCS11_F_RSA_VERIFY, PKCS11_R_DIGEST_TOO_BIG);
		return 0;
	}

	if(type != NID_md5_sha1)
	{
		s=(unsigned char *)OPENSSL_malloc((unsigned int)j+1);
		if (s == NULL)
		{
			PKCS11err(PKCS11_F_RSA_VERIFY, PKCS11_R_MALLOC_FAILURE);
			return 0;
		}
		p=s;
		i2d_X509_SIG(&sig,&p);
	}

	wrapper = pkcs11_getSession();
	if (!wrapper)
		return 0;
	session = wrapper->session;

	hPublicKey = (CK_OBJECT_HANDLE)RSA_get_ex_data(rsa, rsaPubKey);
	if (hPublicKey == CK_INVALID_HANDLE)
		hPublicKey = pkcs11_FindOrCreateKey(session, (RSA *)rsa, CKO_PUBLIC_KEY, true);

	if (hPublicKey != CK_INVALID_HANDLE)
	{
		rv = pFunctionList->C_VerifyInit(session, pMechanism, hPublicKey);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_VERIFY, PKCS11_R_VERIFYINIT, rv);
			goto err;
		}
		ulSigLen = siglen;
		rv = pFunctionList->C_Verify(session, s, i, (CK_BYTE_PTR)sigbuf, ulSigLen);
		if (rv != CKR_OK)
		{
			pkcs11_die(PKCS11_F_RSA_VERIFY, PKCS11_R_VERIFY, rv);
			goto err;
		}
		ret = 1;
	}

err:
	if(type != NID_md5_sha1)
	{
		memset(s,0,(unsigned int)siglen);
		OPENSSL_free(s);
	}
	OPENSSL_free(wrapper);

	return ret;
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

	DBG_fprintf("%s\n", __FUNCTION__);

	aPublicKeyTemplate[6].ulValueLen = BN_num_bytes(bn_e);
	aPublicKeyTemplate[6].pValue = OPENSSL_malloc(aPublicKeyTemplate[6].ulValueLen);
	i = BN_bn2bin(bn_e, aPublicKeyTemplate[6].pValue);
	aPublicKeyTemplate[1].ulValueLen = sizeof(token);
	aPublicKeyTemplate[1].pValue = &token;
	aPrivateKeyTemplate[1].ulValueLen = sizeof(token);
	aPrivateKeyTemplate[1].pValue = &token;

	wrapper = pkcs11_getSession();
	if (!wrapper)
		return 0;
	session = wrapper->session;

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
	/* 	set n */ 
	rsa->n = BN_bin2bn(pModulus->pValue, pModulus->ulValueLen, rsa->n);

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
	/* 	set e */ 
	rsa->e = bn_e;
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

#if 0
RSA* pkcs11_RSA_generate_tmp_key(int bits,unsigned long e_value,void (*callback)(int,int,void *),void *cb_arg)
{
	RSA		*rsa;
	CK_MECHANISM	Mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_BBOOL	token = FALSE;
	unsigned int	deleteKey;

	DBG_fprintf("%s\n", __FUNCTION__);

	rsa=RSA_new();
	if (rsa == NULL)
		return NULL;
	else
	{
		if (pkcs11_RSA_generate_key_with_mechanism(rsa, &Mechanism, bits, e_value, callback, cb_arg, token))
		{
			deleteKey = TRUE;
			RSA_set_ex_data(rsa, deletePubKeyOnFree, (void *)deleteKey);
			RSA_set_ex_data(rsa, deletePrivKeyOnFree, (void *)deleteKey);
			return rsa;
		}
		else
			return NULL;
	}
}
#endif

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

				wrapper = pkcs11_getSession();
				if (!wrapper)
					return 0;
				session = wrapper->session;

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

				wrapper = pkcs11_getSession();
				if (!wrapper)
					return 0;
				session = wrapper->session;

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

static void pkcs11_rand_add(const void *buf,
		int num,
		double entropy)
{
	CK_RV rv;
	struct token_session *wrapper;
 
	DBG_fprintf("%s\n", __FUNCTION__);

	/* return any token */
	wrapper = pkcs11_getSession();
	if (!wrapper)
		return;

	rv = pFunctionList->C_SeedRandom(wrapper->session, (CK_BYTE_PTR)&entropy, sizeof(entropy));
	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_RAND_ADD, PKCS11_R_SEEDRANDOM, rv);
		return; 
	}

	rv = pFunctionList->C_GenerateRandom(wrapper->session, (CK_BYTE *)buf, num);
	if (rv != CKR_OK)
	{
		pkcs11_die(PKCS11_F_RAND_ADD, PKCS11_R_GENERATERANDOM, rv);
	}

	pFunctionList->C_CloseSession(wrapper->session);
	OPENSSL_free(wrapper);
}

static void pkcs11_rand_seed(const void *buf,
		int num)
{
	DBG_fprintf("%s\n", __FUNCTION__);

	pkcs11_rand_add(buf, num, num);
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
	DBG_fprintf("EVP_CIPHER_CTX_mode(ctx): %lu, EVP_CIPH_CBC_MODE: %d, iv: %p, ctx->iv: %p\n",
		    EVP_CIPHER_CTX_mode(ctx), EVP_CIPH_CBC_MODE, iv, ctx->iv);

	if (mech==-1) {
		PKCS11err(PKCS11_F_INITKEY, PKCS11_R_BADMECHANISM);
		goto out;
	} else if (EVP_CIPHER_CTX_mode(ctx) == EVP_CIPH_CBC_MODE) {
		mechanism.pParameter = (CK_VOID_PTR)(iv ? iv : ctx->iv);
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
		const unsigned char *in, unsigned int inlen)
{
	unsigned long outlen = inlen;
	CK_RV rv;
	CK_SESSION_HANDLE session;

	DBG_fprintf("%s\n", __FUNCTION__);

	session = CIPHER_DATA(ctx)->session;

	if (ctx->encrypt) {
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
pkcs11_ripemd_init(EVP_MD_CTX *ctx)
{
	return pkcs11_digest_init(ctx, alg_ripemd);
}

static inline int
pkcs11_digest_init(EVP_MD_CTX *ctx, int alg)
{
	struct pkcs11_digest_ctx *ctx_data = ctx->md_data;

	DBG_fprintf("%s, alg = %d\n", __FUNCTION__, alg);

	memset(ctx_data, 0, sizeof(struct pkcs11_digest_ctx));
	ctx_data->alg = alg;
	ctx_data->ref_cnt = OPENSSL_malloc(sizeof(int));

	DBG_fprintf("%s, ref_cnt = %p\n", __FUNCTION__, ctx_data->ref_cnt);

	*ctx_data->ref_cnt = 0;

	return 1;
}

static int
pkcs11_digest_update(EVP_MD_CTX *ctx, const void *in, size_t len)
{
	struct pkcs11_digest_ctx *ctx_data;

	DBG_fprintf("%s, len = %lu\n", __FUNCTION__, len);

	if (!MD_DATA(ctx)) {
		PKCS11err(PKCS11_F_DIGESTUPDATE, PKCS11_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	ctx_data = (struct pkcs11_digest_ctx *)MD_DATA(ctx);
	
	while (len + ctx_data->len > ctx_data->size) {
		ctx_data->size += PKCS11_DIGEST_BLOCK_SIZE;
		ctx_data->data = realloc(ctx_data->data, ctx_data->size);
	}

	memcpy(ctx_data->data + ctx_data->len, in, len);
	ctx_data->len += len;
	
	return 1;
}

static int
pkcs11_digest_finish(EVP_MD_CTX *ctx, unsigned char *md)
{
	CK_ULONG len = EVP_MD_CTX_size(ctx);
	CK_RV rv;
	struct pkcs11_digest_ctx *data = (struct pkcs11_digest_ctx *)MD_DATA(ctx);
	int ret = 0, alg = data->alg;
	struct token_session *wrapper = pkcs11_getSession();
	CK_MECHANISM_TYPE mech = get_mech(alg, NULL);
	CK_MECHANISM mechanism = {mech, NULL, 0};

	DBG_fprintf("%s\n", __FUNCTION__);

	if (!wrapper)
		goto out;

	switch (alg) {
		case alg_sha:
			mech = CKM_SHA_1;
			break;
		case alg_sha224:
			mech = CKM_SHA224;
			break;
		case alg_sha256:
			mech = CKM_SHA256;
			break;
		case alg_sha384:
			mech = CKM_SHA384;
			break;
		case alg_sha512:
			mech = CKM_SHA512;
			break;
		case alg_md5:
			mech = CKM_MD5;
			break;
		case alg_ripemd:
			mech = CKM_RIPEMD160;
			break;
		default:
			PKCS11err(PKCS11_F_DIGESTFINISH, PKCS11_R_UNKNOWN_ALGORITHM_TYPE);
			ERR_add_error_data(1, alg_to_string(alg));
			goto out_endsession;
			break;
	}

	rv = pFunctionList->C_DigestInit(wrapper->session, &mechanism);
	if (rv != CKR_OK) {
		pkcs11_die(PKCS11_F_DIGESTFINISH, PKCS11_R_DIGESTINIT, rv);
		goto out_endsession;
	}

	rv = pFunctionList->C_Digest(wrapper->session, (CK_BYTE_PTR)data->data, data->len, md,
				     &len);
	if (rv != CKR_OK) {
		pkcs11_die(PKCS11_F_DIGESTFINISH, PKCS11_R_DIGEST, rv);
		goto out_endsession;
	}

	if (*data->ref_cnt == 0) {
		OPENSSL_free(data->data);
		OPENSSL_free(data->ref_cnt);
	} else
		*(data->ref_cnt) -= 1;

	memset(data, 0, sizeof(struct pkcs11_digest_ctx));
	ret = 1;
	
out_endsession:
	pFunctionList->C_CloseSession(wrapper->session);
	OPENSSL_free(wrapper);
out:
	return ret;
}

static int
pkcs11_digest_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
	struct pkcs11_digest_ctx *data = out->md_data;
#if 0
	struct pkcs11_digest_ctx *indata = in->md_data;

	/* TODO: change this to a refcount */
	data->data = (char *)OPENSSL_malloc(data->len);
	memcpy(data->data, indata->data, data->len);
#else
	DBG_fprintf("%s, ref_cnt addr: %p, val: %d\n", __FUNCTION__, data->ref_cnt,
		    *(data->ref_cnt));

	*(data->ref_cnt) += 1;
	
	DBG_fprintf("%s, ref_cnt addr: %p, val: %d\n", __FUNCTION__, data->ref_cnt,
		    *(data->ref_cnt));
#endif

	return 1;
}

static inline int
pkcs11_digest_cleanup(EVP_MD_CTX *ctx)
{
	return 1;
}
#endif
#endif

