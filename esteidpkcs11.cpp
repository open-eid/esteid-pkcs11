/*
 * ESTEID PKCS11 module
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL) or the BSD License (see LICENSE.BSD).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 *
 */

#include "Logger.h"
#include "precompiled.h"

#ifdef ONE_PIN
#include "OnePinPKCS11Context.h"
#else
#include "PKCS11Context.h"
#endif

#ifdef _WIN32
#include <crtdbg.h>
#endif

#ifdef _MANAGED
#pragma managed(push, off)
#endif

#if defined(_WIN32)

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
  FLOG;
  CHAR name[MAX_PATH + 1] = "\0";
	char *reason = "";

	GetModuleFileName(GetModuleHandle(NULL),name,MAX_PATH);

	switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        reason = "Attach Process";
        break;
      case DLL_THREAD_ATTACH:
        reason = "Attach Thread";
        break;
      case DLL_THREAD_DETACH:
        reason = "Detach Thread";
        break;
      case DLL_PROCESS_DETACH:
        reason = "Detach Process";
        break;
	}
	_log("********** DllMain Module(handle:0x%X) '%s'; reason='%s'; Reserved=%p; P:%d; T:%d\n",
  			hModule, name, reason, lpReserved, GetCurrentProcessId(), GetCurrentThreadId());
  return TRUE;
}
#endif

#ifdef _MANAGED
#pragma managed(pop)
#endif

PKCS11Context *ctx = NULL;

extern "C" CK_DECLARE_FUNCTION(CK_RV, C_Initialize(CK_VOID_PTR pInitArgs)) {
  try {
    FLOG;
#ifdef ONE_PIN
    ctx = new OnePinPKCS11Context();
#else
    ctx = new PKCS11Context();
#endif
    _log("C_Initialize OK");
  } catch (std::runtime_error &e) {
    _log("Failed to initialize pkcs11: %s", e.what());
  }
  return CKR_OK;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_Finalize(CK_VOID_PTR   pReserved)) {
    FLOG;
	if (ctx)
		delete ctx;
	ctx = NULL;
	return CKR_OK;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetInfo(CK_INFO_PTR   pInfo  )) {
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_GetInfo(pInfo);
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetSlotList(
		CK_BBOOL       tokenPresent,  /* only slots with tokens? */
		CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
		CK_ULONG_PTR   pulCount)) {   /* receives number of slots */
    FLOG;
	if (!ctx) {
    _log("returning CKR_CRYPTOKI_NOT_INITIALIZED");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
	return ctx->C_GetSlotList(tokenPresent,pSlotList,pulCount);
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetTokenInfo(
		CK_SLOT_ID        slotID,  /* ID of the token's slot */
		CK_TOKEN_INFO_PTR pInfo)) {/* receives the token information */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_GetTokenInfo(slotID,pInfo);
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetSlotInfo(
		CK_SLOT_ID       slotID,  /* the ID of the slot */
		CK_SLOT_INFO_PTR pInfo)) {/* receives the slot information */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_GetSlotInfo(slotID,pInfo);
	}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetMechanismList(
		CK_SLOT_ID            slotID,          /* ID of token's slot */
		CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
		CK_ULONG_PTR          pulCount)) {     /* gets # of mechs. */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_GetMechanismList(slotID,pMechanismList,pulCount);
	}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetMechanismInfo(
		CK_SLOT_ID            slotID,  /* ID of the token's slot */
		CK_MECHANISM_TYPE     type,    /* type of mechanism */
		CK_MECHANISM_INFO_PTR pInfo)) {/* receives mechanism info */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_GetMechanismInfo(slotID,type,pInfo);
	}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_InitToken(
		CK_SLOT_ID      slotID,    /* ID of the token's slot */
		CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
		CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
		CK_UTF8CHAR_PTR pLabel)) { /* 32-byte token label (blank padded) */
  FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_InitToken(slotID,pPin,ulPinLen,pLabel);
	}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_OpenSession(
		CK_SLOT_ID            slotID,        /* the slot's ID */
		CK_FLAGS              flags,         /* from CK_SESSION_INFO */
		CK_VOID_PTR           pApplication,  /* passed to callback */
		CK_NOTIFY             Notify,        /* callback function */
		CK_SESSION_HANDLE_PTR phSession)) {  /* gets session handle */
  FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_OpenSession(slotID,flags,pApplication,Notify,phSession);
	}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_CloseSession(CK_SESSION_HANDLE hSession)) {  /* the session's handle */
  FLOG;
  if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return ctx->C_CloseSession(hSession);
}
extern "C" CK_DECLARE_FUNCTION(CK_RV,C_CloseAllSessions(
		CK_SLOT_ID     slotID )) {  /* the token's slot */
  FLOG;
  if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return ctx->C_CloseAllSessions(slotID);
	}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetSessionInfo(
		CK_SESSION_HANDLE   hSession,  /* the session's handle */
		CK_SESSION_INFO_PTR pInfo)) {  /* receives session info */
  FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_GetSessionInfo(hSession,pInfo);
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_FindObjectsInit(
		CK_SESSION_HANDLE hSession,   /* the session's handle */
		CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
		CK_ULONG          ulCount)) { /* attrs in search template */
  FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_FindObjectsInit(hSession,pTemplate,ulCount);
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_FindObjects(
		CK_SESSION_HANDLE    hSession,          /* session's handle */
		CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
		CK_ULONG             ulMaxObjectCount,  /* max handles to get */
		CK_ULONG_PTR         pulObjectCount)) { /* actual # returned */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_FindObjects(hSession,phObject,ulMaxObjectCount,pulObjectCount);
	}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_FindObjectsFinal(
		CK_SESSION_HANDLE hSession  /* the session's handle */)) {
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_FindObjectsFinal(hSession);
	}

extern "C"  CK_DECLARE_FUNCTION(CK_RV,C_Login(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_USER_TYPE      userType,  /* the user type */
		CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
		CK_ULONG          ulPinLen)){/* the length of the PIN */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_Login(hSession,userType,pPin,ulPinLen);
	}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_Logout(
		CK_SESSION_HANDLE hSession)) { /* the session's handle */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_Logout(hSession);
	}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetAttributeValue(
	CK_SESSION_HANDLE hSession,   /* the session's handle */
	CK_OBJECT_HANDLE  hObject,    /* the object's handle */
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
	CK_ULONG          ulCount)) { /* attributes in template */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_GetAttributeValue(hSession,hObject,pTemplate,ulCount);
	}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_SignInit(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
	CK_OBJECT_HANDLE  hKey         /* handle of signature key */
	)) {
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_SignInit(hSession,pMechanism,hKey);
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_Sign(
	CK_SESSION_HANDLE hSession,        /* the session's handle */
	CK_BYTE_PTR       pData,           /* the data to sign */
	CK_ULONG          ulDataLen,       /* count of bytes to sign */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
	)) {
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_Sign(hSession,pData,ulDataLen,pSignature,pulSignatureLen);
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_SignUpdate(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_BYTE_PTR       pPart,     /* the data to sign */
		CK_ULONG          ulPartLen  /* count of bytes to sign */
		)) {
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_SignUpdate(hSession,pPart,ulPartLen);
}
extern "C" CK_DECLARE_FUNCTION(CK_RV,C_SignFinal(
		CK_SESSION_HANDLE hSession,        /* the session's handle */
		CK_BYTE_PTR       pSignature,      /* gets the signature */
		CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
		)) {
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return ctx->C_SignFinal(hSession,pSignature,pulSignatureLen);
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_VerifyInit(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
	CK_OBJECT_HANDLE  hKey)) {    /* verification key */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_Verify(
	CK_SESSION_HANDLE hSession,       /* the session's handle */
	CK_BYTE_PTR       pData,          /* signed data */
	CK_ULONG          ulDataLen,      /* length of signed data */
	CK_BYTE_PTR       pSignature,     /* signature */
	CK_ULONG          ulSignatureLen)){/* signature length*/
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_VerifyUpdate(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen)){/* length of signed data */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_VerifyFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen)){/* signature length */
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_SeedRandom(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_BYTE_PTR       pSeed,     /* the seed material */
	CK_ULONG          ulSeedLen  /* length of seed material */
))
{
    FLOG;
	if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GenerateRandom(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_BYTE_PTR       RandomData,/* receives the random data */
	CK_ULONG          ulRandomLen  /* number of bytes to be generated */
))
{
  FLOG;
    if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_FUNCTION_LIST function_list = {
	{2,20},
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList))
{
  FLOG
	*ppFunctionList = &function_list;
	return CKR_OK;
}

//Stubs

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey))
{
  if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return ctx->C_DecryptInit(hSession,pMechanism,hKey);
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen))
{
  if (!ctx) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return ctx->C_Decrypt(hSession,pEncryptedData,ulEncryptedDataLen, pData, pulDataLen);
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_GetFunctionStatus(CK_SESSION_HANDLE hSession))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_CancelFunction(CK_SESSION_HANDLE hSession))
{
  _log("RETURNING CKR_FUNCTION_NOT_SUPPORTED");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

extern "C" CK_DECLARE_FUNCTION(CK_RV,C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR)) {
  _log("RETURNING CKR_GENERAL_ERROR");
  return CKR_FUNCTION_NOT_SUPPORTED;
}