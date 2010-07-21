
#ifndef _HW_PKCS11_H_
#define _HW_PKCS11_H_




struct _token {
	struct _token *token_next;	/* next token in list of all tokens */
	CK_SLOT_ID slot;		/* slot ID of this token */
};

/* Future:
 *   Lists for free (non-busy) rsa,des... tokens.
 */

struct _token *pkcs11_token_list = NULL;

struct _token *pkcs11_rsa_head = NULL;
struct _token *pkcs11_des_head = NULL;
struct _token *pkcs11_tdes_head = NULL;
struct _token *pkcs11_sha_head = NULL;
struct _token *pkcs11_dh_head = NULL;
struct _token *pkcs11_aes_head = NULL;
struct _token *pkcs11_ripemd_head = NULL;
struct _token *pkcs11_ssl3_head = NULL;
struct _token *pkcs11_md5_head = NULL;

enum alg_type { alg_rsa=1, alg_des, alg_tdes, alg_sha, alg_dh, alg_aes,
		alg_ripemd, alg_ssl3, alg_md5, alg_rand,
		alg_sha224,alg_sha256,alg_sha384,alg_sha512 };

#endif
