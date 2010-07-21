/* hw_pkcs11_err.c */
/*
 * PKCS#11 engine for the OpenSSL project 2002
 * Developped by Bull Trustway R&D Networking & Security
 * Introduced and tested with Bull TrustWay CC2000 crypto hardware
 * Afchine.Madjlessi@bull.net Bull S.A. France
 * http://www.servers.bull.com/trustway
 */

#include <stdio.h>
#include <openssl/err.h>
#include "e_pkcs11_err.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR
static ERR_STRING_DATA pkcs11_str_functs[]=
{
    {ERR_PACK(0,PKCS11_F_INIT,0),	    "PKCS11_INIT"},
    {ERR_PACK(0,PKCS11_F_FINISH,0),	    "PKCS11_FINISH"},
    {ERR_PACK(0,PKCS11_F_DESTROY,0),	    "PKCS11_DESTROY"},
    {ERR_PACK(0,PKCS11_F_CTRL,0),	    "PKCS11_CTRL"},
    {ERR_PACK(0,PKCS11_F_RSA_INIT,0),	    "PKCS11_RSA_INIT"},
    {ERR_PACK(0,PKCS11_F_RSA_FINISH,0),	    "PKCS11_RSA_FINISH"},
    {ERR_PACK(0,PKCS11_F_FINDORCREATEKEY,0),"PKCS11_FINDORCREATEKEY"},
    {ERR_PACK(0,PKCS11_F_RSA_GEN_KEY,0),    "PKCS11_RSA_GEN_KEY"},
    {ERR_PACK(0,PKCS11_F_RSA_PUB_ENC,0),    "PKCS11_RSA_PUB_ENC"},
    {ERR_PACK(0,PKCS11_F_RSA_PRIV_ENC,0),   "PKCS11_RSA_PRIV_ENC"},
    {ERR_PACK(0,PKCS11_F_RSA_PUB_DEC,0),    "PKCS11_RSA_PUB_DEC"},
    {ERR_PACK(0,PKCS11_F_RSA_PRIV_DEC,0),   "PKCS11_RSA_PRIV_DEC"},
    {ERR_PACK(0,PKCS11_F_RSA_SIGN,0),	    "PKCS11_RSA_SIGN"},
    {ERR_PACK(0,PKCS11_F_RSA_VERIFY,0),	    "PKCS11_RSA_VERIFY"},
    {ERR_PACK(0,PKCS11_F_RAND_ADD,0),	    "PKCS11_RAND_ADD"},
    {ERR_PACK(0,PKCS11_F_RAND_BYTES,0),	    "PKCS11_RAND_BYTES"},
    {ERR_PACK(0,PKCS11_F_GETSESSION,0),	    "PKCS11_GETSESSION"},
    {ERR_PACK(0,PKCS11_F_FREESESSION,0),    "PKCS11_FREESESSION"},
    {ERR_PACK(0,PKCS11_F_INITKEY,0),        "PKCS11_INITKEY"},
    {ERR_PACK(0,PKCS11_F_DIGESTINIT,0),    "PKCS11_DIGESTINIT"},
    {ERR_PACK(0,PKCS11_F_DIGESTUPDATE,0),    "PKCS11_DIGESTUPDATE"},
    {ERR_PACK(0,PKCS11_F_DIGESTFINISH,0),    "PKCS11_DIGESTFINISH"},
    {ERR_PACK(0,PKCS11_F_CIPHER_UPDATE,0),    "PKCS11_CIPHER_UPDATE"},
    {ERR_PACK(0,PKCS11_F_PREINIT,0),    "PKCS11_PREINIT"},
    {ERR_PACK(0,PKCS11_F_ADDTOKEN,0),    "PKCS11_ADDTOKEN"},
    {ERR_PACK(0,PKCS11_F_LOAD_PRIVKEY,0),    "PKCS11_LOAD_PRIVKEY"},
    {ERR_PACK(0,PKCS11_F_LOAD_PUBKEY,0),    "PKCS11_LOAD_PUBKEY"},
    {ERR_PACK(0,PKCS11_F_DIGESTCOPY,0),    "PKCS11_DIGESTCOPY"},
    {0,NULL}
};

static ERR_STRING_DATA pkcs11_str_reasons[]=
{
    {PKCS11_R_ALREADY_LOADED                 ,"PKCS#11 DSO already loaded"},
    {PKCS11_R_DSO_FAILURE                    ,"unable to load PKCS#11 DSO"},
    {PKCS11_R_NOT_LOADED                     ,"PKCS#11 DSO not loaded"},
    {PKCS11_R_PASSED_NULL_PARAMETER          ,"null parameter passed"},
    {PKCS11_R_COMMAND_NOT_IMPLEMENTED        ,"command not implemented"},
    {PKCS11_R_INITIALIZE                     ,"C_Initialize failed"},
    {PKCS11_R_FINALIZE                       ,"C_Finalize failed"},
    {PKCS11_R_GETINFO                        ,"C_GetInfo faile"},
    {PKCS11_R_GETSLOTLIST                    ,"C_GetSlotList failed"},
    {PKCS11_R_NO_MODULUS_OR_NO_EXPONENT      ,"no modulus or no exponent"},
    {PKCS11_R_ATTRIBUT_SENSITIVE_OR_INVALID  ,"attrribute sensitive or invalid	"},
    {PKCS11_R_GETATTRIBUTVALUE               ,"C_GetAttributeValue failed"},
    {PKCS11_R_NO_MODULUS                     ,"no modulus"},
    {PKCS11_R_NO_EXPONENT                    ,"no exponent"},
    {PKCS11_R_FINDOBJECTSINIT                ,"C_FindObjectsInit failed"},
    {PKCS11_R_FINDOBJECTS                    ,"C_FindObjects failed"},
    {PKCS11_R_FINDOBJECTSFINAL               ,"C_FindObjectsFinal failed"},
    {PKCS11_R_OBJECT_NOT_FOUND               ,"object not found"},
    {PKCS11_R_CREATEOBJECT                   ,"C_CreateObject failed"},
    {PKCS11_R_DESTROYOBJECT                  ,"C_DestroyObject failed"},
    {PKCS11_R_OPENSESSION                    ,"C_OpenSession failed"},
    {PKCS11_R_CLOSESESSION                   ,"C_CloseSession failed"},
    {PKCS11_R_ENCRYPTINIT                    ,"C_EncryptInit failed"},
    {PKCS11_R_ENCRYPT                        ,"C_Encrypt failed"},
    {PKCS11_R_SIGNINIT                       ,"C_SignInit failed"},
    {PKCS11_R_SIGN                           ,"C_Sign failed"},
    {PKCS11_R_DECRYPTINIT                    ,"C_DecryptInit failed"},
    {PKCS11_R_DECRYPT                        ,"C_Decrypt failed"},
    {PKCS11_R_VERIFYINIT                     ,"C_VerifyRecover failed"},
    {PKCS11_R_VERIFY                         ,"C_Verify failed	"},
    {PKCS11_R_VERIFYRECOVERINIT              ,"C_VerifyRecoverInit failed"},
    {PKCS11_R_VERIFYRECOVER                  ,"C_VerifyRecover failed"},
    {PKCS11_R_GEN_KEY                        ,"C_GenerateKeyPair failed"},
    {PKCS11_R_SEEDRANDOM                     ,"C_SeedRandom failed"},
    {PKCS11_R_GENERATERANDOM                 ,"C_GenerateRandom failed"},
    {PKCS11_R_INVALID_MESSAGE_LENGTH         ,"invalid message length"},
    {PKCS11_R_UNKNOWN_ALGORITHM_TYPE         ,"unknown algorithm type"},
    {PKCS11_R_UNKNOWN_ASN1_OBJECT_ID         ,"unknown asn1 onject id"},
    {PKCS11_R_UNKNOWN_PADDING_TYPE           ,"unknown padding type"},
    {PKCS11_R_DIGEST_TOO_BIG                 ,"digest too big"},
    {PKCS11_R_MALLOC_FAILURE                 ,"malloc failure"},
    {PKCS11_R_CTRL_COMMAND_NOT_IMPLEMENTED   ,"control command not implemented"},
    {PKCS11_R_GETSLOTINFO		     ,"C_GetSlotInfo failed"},
    {PKCS11_R_GETMECHANISMLIST		     ,"C_GetMechanismList failed"},
    {PKCS11_R_GETMECHANISMINFO		     ,"C_GetMechanismInfo failed"},
    {PKCS11_R_BADMECHANISM		     ,"bad mechanism"},
    {PKCS11_R_DIGESTINIT		     ,"C_DigestInit failed"},
    {PKCS11_R_DIGESTUPDATE		     ,"C_DigestUpdate failed"},
    {PKCS11_R_DIGESTFINAL		     ,"C_DigestFinal failed"},
    {PKCS11_R_NOTOKENS			     ,"no hardware tokens found"},
    {PKCS11_R_NOTOKENFORALGORITHM	     ,"no tokens available to accelerate algorithm"},
    {PKCS11_R_DIGEST			     ,"C_Digest failed"},
    {0,NULL}
};

#endif	

static int pkcs11_lib_error_code=0;
static int pkcs11_error_init=1;

void ERR_load_pkcs11_strings(void)
{
    if (pkcs11_lib_error_code == 0)
	pkcs11_lib_error_code = ERR_get_next_error_library();

    if (pkcs11_error_init)
    {
	pkcs11_error_init=0;
#ifndef OPENSSL_NO_ERR
	ERR_load_strings(pkcs11_lib_error_code,pkcs11_str_functs);
	ERR_load_strings(pkcs11_lib_error_code,pkcs11_str_reasons);
#endif
    }
}

void ERR_unload_pkcs11_strings(void)
{
    if (pkcs11_error_init == 0)
    {
#ifndef OPENSSL_NO_ERR
	ERR_unload_strings(pkcs11_lib_error_code,pkcs11_str_functs);
	ERR_unload_strings(pkcs11_lib_error_code,pkcs11_str_reasons);
#endif
	pkcs11_error_init = 1;
    }
}

void ERR_pkcs11_error(int function, int reason, char *file, int line)
{
    if (pkcs11_lib_error_code == 0)
	pkcs11_lib_error_code=ERR_get_next_error_library();
    ERR_PUT_error(pkcs11_lib_error_code,function,reason,file,line);
    //ERR_print_errors_fp(stderr);
}
