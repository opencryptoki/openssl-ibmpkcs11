
#ifndef _HW_PKCS11_H_
#define _HW_PKCS11_H_

/* Number of NID's that exist in OpenSSL 1.0.0a */
#define NUM_NID 893

struct _token {
	struct _token *token_next;	/* next token in list of all tokens */
	CK_SLOT_ID slot_id;		/* slot ID of this token */
	int pkcs11_implemented_ciphers[NUM_NID];
	int pkcs11_implemented_digests[NUM_NID];
};

struct _token *pkcs11_token_list = NULL;
struct _token *pkcs11_token = NULL;

enum alg_type { alg_rsa=1, alg_des, alg_tdes, alg_sha, alg_dh, alg_aes,
		alg_ripemd, alg_ssl3, alg_md5, alg_rand,
		alg_sha224,alg_sha256,alg_sha384,alg_sha512 };

#endif
