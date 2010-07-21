/* cryptoki.h include file for PKCS #11. */
/* $Revision$ */

/* License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
 * (Cryptoki)" in all material mentioning or referencing this software.

 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)" in all material mentioning or 
 * referencing the derived work.

 * RSA Security Inc. makes no representations concerning either the 
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */

/* 
  Modified IBM 2008. Multiplatform support
 */

#ifndef ___CRYPTOKI_H_INC___
#define ___CRYPTOKI_H_INC___

/* We don't pack our structures in openCryptoki, which will lead to alignment issues if the
 * engine expects them to be */
#ifndef OPENCRYPTOKI
#pragma pack(push, cryptoki, 1)
#endif

#if defined(AIX) || defined(HPUX) || defined(SOLARIS) || defined(LINUX) || defined(LINUX64) || defined(_IA64) | defined(AIX64) || defined(__LP64__)

#  define CK_ENTRY
#  define CK_CALLBACK_ENTRY
#  define CK_IMPORT_SPEC
#  define CK_CALL_SPEC

#elif defined(OS2)

#  define CK_ENTRY
#  define CK_CALLBACK_ENTRY _Optlink
#  define CK_IMPORT_SPEC
#  define CK_CALL_SPEC

#elif defined(WIN32)

#  define CK_ENTRY __declspec( dllexport )
#  define CK_CALLBACK_ENTRY
#  define CK_IMPORT_SPEC __declspec(dllimport)
#  define CK_CALL_SPEC __cdecl


#else

#  error "Includes not defined for this platform."

#endif

/* Define CRYPTOKI_EXPORTS during the build of cryptoki libraries. Do
 * not define it in applications.
 */
#ifdef CRYPTOKI_EXPORTS
/* Specified that the function is an exported DLL entry point. */
#define CK_EXPORT_SPEC __declspec(dllexport) 
#else
#define CK_EXPORT_SPEC CK_IMPORT_SPEC 
#endif

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

#define CK_CALLBACK_FUNCTION(returnType, name)  \
    returnType (CK_CALL_SPEC CK_PTR name)    

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#ifndef OPENCRYPTOKI
#pragma pack(pop, cryptoki)
#endif

#endif /* ___CRYPTOKI_H_INC___ */
