/*
 * ESTEID PKCS11 module
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL)
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 *
 */
#include <string.h>
#include <stdio.h>
#include "precompiled.h"
#include "PKCS11Context.h"
#include "utility/EstEID_utility.h"
#include "utility/asnCertificate.h"
#include <map>
#include "Logger.h"

#undef min

#define MAX_IDCARD_COUNT 10

enum ObjID {
  OBJ_INVALID,
  OBJ_CERT,
  OBJ_PRIVKEY,
  OBJ_PUBKEY
};

class PKCS11Object;

class searchTerm;

typedef std::vector<PKCS11Object >::iterator objectIter;
typedef std::vector<CK_ATTRIBUTE >::iterator attrIter;

class ObjHandle {
  CK_OBJECT_HANDLE h;
public:
  ObjHandle & operator = (const PKCS11Object &obj);
  
  ObjHandle(const ObjID &handle) : h(handle) {
  }
  
  ObjHandle(const CK_OBJECT_HANDLE &handle) : h(handle) {
  }
  
  ObjHandle() : h(OBJ_INVALID) {
  }
  
  bool operator ==(const ObjHandle &other) {
    return h == other.h;
  }
};

class PKCS11Object {
protected:
  ObjHandle handle;
  std::vector<CK_ATTRIBUTE> attrib;
  
  friend class ObjHandle;
  
  friend class searchTerm;
  
public:
  PKCS11Object(ObjID id, CK_ATTRIBUTE *att, size_t count) :
  handle(id), attrib(att, att + count) {
  }
  
  bool operator ==(const ObjHandle &objHandle) {
    return handle == objHandle;
  }
  
  attrIter findAttrib(CK_ATTRIBUTE_PTR att) {
    return find(attrib.begin(), attrib.end(), att->type);
  }
  
  void appendAttrib(CK_ATTRIBUTE att) {
    attrib.push_back(att);
  }
  
  bool noAttrib(attrIter &ref) {
    return ref == attrib.end();
  }
};

ObjHandle & ObjHandle::operator = (const PKCS11Object &obj) {
  h = obj.handle.h;
  return *this;
}

CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
CK_BBOOL _true = CK_TRUE;
CK_BBOOL _false = CK_FALSE;
CK_KEY_TYPE keyType = CKK_RSA;

CK_ATTRIBUTE publicKeyTemplate[] = {
  {CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
  {CKA_TOKEN, &_true, sizeof(_true)},
  {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
  {CKA_ENCRYPT, &_true, sizeof(_true)},
  //{CKA_VERIFY, &_true, sizeof(_true)},
  //    {CKA_MODULUS_BITS, &modBits, sizeof(modBits)},
  {CKA_ALWAYS_AUTHENTICATE, &_false, sizeof(_false)},
};
CK_ATTRIBUTE privateKeyTemplate[] = {
  {CKA_CLASS, &privkey_class, sizeof(privkey_class)},
  {CKA_TOKEN, &_true, sizeof(_true)},
  {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
  {CKA_PRIVATE, &_true, sizeof(_true)},
  {CKA_SIGN, &_true, sizeof(_true)},
  {CKA_DECRYPT, &_true, sizeof(_true)},
  {CKA_ALWAYS_AUTHENTICATE, &_false, sizeof(_false)},
};
CK_ATTRIBUTE certificateTemplate[] = {
  {CKA_CLASS, &cert_class, sizeof(cert_class)},
  {CKA_TOKEN, &_true, sizeof(_true)},
  {CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type)},
  {CKA_TRUSTED, &_true, sizeof(_true)},
};

class PKCS11Session {
public:
  struct utf8str : public std::vector<CK_UTF8CHAR> {
    utf8str & operator = (const std::string _in) {
      resize(_in.length());
      std::copy(_in.begin(), _in.end(), begin());
      return *this;
    }
  };
private:
  friend class PKCS11Context;
  
  //	friend struct SessionChangeState;
  CK_SESSION_HANDLE session;
  CK_SLOT_ID slotID;
  int readerID;
  CK_FLAGS flags;
  CK_VOID_PTR pApplication;
  CK_NOTIFY notify;
  std::vector<CK_ATTRIBUTE > searchParam;
  std::vector<ObjHandle> searchHandles;
  std::vector<PKCS11Object> objects;
  std::vector<byte> dataToSign;
  struct certFields {
    CK_BYTE id;
    ByteVec cert;
    ByteVec pubKey;
    ByteVec iss;
    ByteVec ser;
    ByteVec sub;
    ByteVec modulus;
    ByteVec publicExponent;
    utf8str label;
    CK_ULONG modulusBits;
  } auth, sign;
  PinString pin;
  CK_ULONG state;
  CK_MECHANISM sigMechanism;
public:
  struct changeState {
    CK_ULONG mState;
    CK_SLOT_ID mSlot;
    PinString mPin;
    
    changeState(CK_SLOT_ID slot, CK_ULONG state, PinString pin)
    : mState(state), mSlot(slot), mPin(pin) {
    }
    
    void operator ()(PKCS11Session &obj) {
      if (obj.slotID == mSlot) {
        obj.state = mState;
        obj.pin = mPin;
      }
    }
  };
  
  PKCS11Session(CK_SESSION_HANDLE, CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY);
  
  ~PKCS11Session();
  
  bool operator ==(const CK_SESSION_HANDLE& other) {
    return session == other;
  }

  void createCertificate(ByteVec certBlob, certFields & _a, std::string label, CK_BYTE id) {
    FLOG;

    _a.cert = certBlob;
    std::stringstream dummy;
    asnCertificate asnCert(_a.cert, dummy);
    _a.id = id;
    _a.pubKey = asnCert.getPubKey();

    _a.iss = asnCert.getIssuerBlob();
    _a.ser = asnCert.getSerialBlob();
    _a.sub = asnCert.getSubjectBlob();
    _a.label = label;
    _a.modulus = asnCert.getModulus();
    _a.publicExponent = asnCert.getPublicExponent();


    vector<byte>::iterator iter;
    FLOG
    vector<byte> v = asnCert.getModulus();
    char tmp[2048];
    char tmp1[33];
    tmp[0] = '\0';
    FLOG
    for(iter = v.begin();iter != v.end();iter++) {
      sprintf(tmp1, "%02x ", *iter);
      strcat(tmp, tmp1);
    }
    _log("-----------------------------size = %i,  public modulus = %s", v.size(), tmp);

    vector<byte> b = asnCert.getPublicExponent();

    CK_ATTRIBUTE valId = {CKA_ID, &_a.id, sizeof(_a.id)};
    CK_ATTRIBUTE valAttCert = {CKA_VALUE, &_a.cert[0], (CK_ULONG) _a.cert.size()};
    CK_ATTRIBUTE valIssuer = {CKA_ISSUER, &_a.iss[0], (CK_ULONG) _a.iss.size()};
    CK_ATTRIBUTE valSerial = {CKA_SERIAL_NUMBER, &_a.ser[0], (CK_ULONG) _a.ser.size()};

    CK_ATTRIBUTE valSubject = {CKA_SUBJECT, &_a.sub[0], (CK_ULONG) _a.sub.size()};
    CK_ATTRIBUTE valLabel = {CKA_LABEL, &_a.label[0], (CK_ULONG) _a.label.size()};

    CK_ATTRIBUTE valAttPubKey = {CKA_VALUE, &_a.pubKey[0], (CK_ULONG) _a.pubKey.size()};
    CK_ATTRIBUTE valLabel0 = {CKA_LABEL, &_a.label[0], (CK_ULONG) label.size()};
    CK_ATTRIBUTE valModulus = {CKA_MODULUS, &_a.modulus[0], (CK_ULONG) _a.modulus.size()};
    CK_ATTRIBUTE valPublicExponent = {CKA_PUBLIC_EXPONENT, &_a.publicExponent[0], (CK_ULONG) _a.publicExponent.size()};

    _a.modulusBits = _a.modulus.size() * 8;
    CK_ATTRIBUTE valModulusBits = {CKA_MODULUS_BITS, &_a.modulusBits, sizeof(_a.modulusBits)};

    CK_ATTRIBUTE valLabel1 = {CKA_LABEL, strdup((char*)&_a.label[0]), (CK_ULONG) label.size()};

    objects.push_back(PKCS11Object(OBJ_CERT, certificateTemplate, LENOF(certificateTemplate)));
    (--(objects.end()))->appendAttrib(valId);
    (--(objects.end()))->appendAttrib(valAttCert);
    (--(objects.end()))->appendAttrib(valIssuer);
    (--(objects.end()))->appendAttrib(valSerial);
    (--(objects.end()))->appendAttrib(valSubject);
    (--(objects.end()))->appendAttrib(valLabel);

    objects.push_back(PKCS11Object(OBJ_PUBKEY, publicKeyTemplate, LENOF(publicKeyTemplate)));
    (--objects.end())->appendAttrib(valId);
    (--objects.end())->appendAttrib(valAttPubKey);
    (--objects.end())->appendAttrib(valLabel0);
    (--objects.end())->appendAttrib(valModulus);
    (--objects.end())->appendAttrib(valPublicExponent);
    (--objects.end())->appendAttrib(valModulusBits);


    objects.push_back(PKCS11Object(OBJ_PRIVKEY, privateKeyTemplate, LENOF(privateKeyTemplate)));
    (--objects.end())->appendAttrib(valId);
    (--objects.end())->appendAttrib(valLabel1);
    (--objects.end())->appendAttrib(valModulus);
    (--objects.end())->appendAttrib(valPublicExponent);
  }
};

bool operator ==(CK_ATTRIBUTE x, CK_ATTRIBUTE_TYPE a) {
  return x.type == a;
}

bool PKCS11Context::checkSlot(CK_SLOT_ID slotID) {
  return (slotID >= (mgr->getTokenCount(true) * 2));
}

PKCS11Context::PKCS11Context(void) {
  init();
}

PKCS11Context::PKCS11Context(CardManager *manager) {
  FLOG
  init();
  if (mgr) {
    delete mgr;
    mgr = NULL;
  }
  mgr = manager;
}

//use init method here because constructor delegating is not possible in VS2010
void PKCS11Context::init() {
  FLOG;
  nextSession = 303;
  mgr = new EstEIDCardAdapter();
  sessions.reserve(MAX_IDCARD_COUNT * 2);
  FLOG;
}

PKCS11Context::~PKCS11Context(void) {
  FLOG;
  //do not free manager in unit tests
#ifndef TEST_MODE
  FLOG
  if (mgr) {
    delete mgr;
    mgr = NULL;
  }
#endif
}

PKCS11Session::PKCS11Session(CK_SESSION_HANDLE sh, CK_SLOT_ID s, CK_FLAGS f, CK_VOID_PTR app, CK_NOTIFY n) :
session(sh), slotID(s), flags(f), pApplication(app), notify(n), state(CKS_RO_PUBLIC_SESSION){
  
  FLOG;
}

PKCS11Session::~PKCS11Session(void) {
  _log("Session %i", session);
}

CK_SESSION_HANDLE PKCS11Context::getNextSessionHandle() {
  FLOG;
  return ++nextSession;
}

void padString(CK_UTF8CHAR *s, int len, std::string rstr) {
  FLOG;
  memset(s, ' ', (size_t) len);
  memcpy(s, rstr.c_str(), std::min((int) rstr.length(), len));
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_GetInfo(CK_INFO_PTR pInfo  )) {
  FLOG;
  
  pInfo->cryptokiVersion.major = 2;
  pInfo->cryptokiVersion.minor = 20;
  padString(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "EstEID (pkcs11 opensource)");
  pInfo->flags = 0;
  padString(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), "EstEID PKCS#11 Library");
  pInfo->libraryVersion.major = 0;
  pInfo->libraryVersion.minor = 1;
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_GetTokenInfo(
                                                         CK_SLOT_ID slotID,  /* ID of the token's slot */
                                                         CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
                                                         )) {
  FLOG;
  
  try {
    unsigned int readerId = slotID / 2;
    
    _log("slotID = %i, reader id = %i", slotID, readerId);
    
    if (checkSlot(slotID)) {
      return CKR_SLOT_ID_INVALID;
    }

    createCardManager(readerId);

    if (!cardm.isInReader(readerId)) {
      return CKR_DEVICE_REMOVED;
    }

    FLOG
    
    char nameBuffer[128];
    std::string name = "";
    std::string documentID = cardm.readDocumentID();
    
    cardm.readCardName();
    if (cardm.isDigiID()) {
      name = cardm.readCardName(TRUE);
    }
    else {
      cp1250_to_utf8(nameBuffer, (char*)cardm.readCardName(TRUE).c_str());
      name = nameBuffer;
    }

    FLOG;
    
     name += IS_SIGN_SLOT ? " (PIN2, Sign)" : " (PIN1, Auth)";
    _log("C_GetTokenInfo %s", name.c_str());
    
    memset(pInfo, 0, sizeof(*pInfo));
    padString(pInfo->label, sizeof(pInfo->label), name);
    padString(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "EstEid smartcardpp");
    padString(pInfo->model, sizeof(pInfo->model), "original");
    padString(pInfo->serialNumber, sizeof(pInfo->serialNumber), documentID);
    pInfo->flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
    
    if (cardm.isSecureConnection()) {
      pInfo->flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
    }
    
    byte credentials[3];
    cardm.getRetryCounts(credentials[2], credentials[0], credentials[1]);
    _log("retries count pin1 %i, pin2 %i, puk %i", credentials[0], credentials[1], credentials[2]);
    
    if (credentials[SIGN_SLOT] < 3) {
      pInfo->flags |= CKF_USER_PIN_COUNT_LOW;
    }
    if (credentials[SIGN_SLOT] == 1) {
      pInfo->flags |= CKF_USER_PIN_FINAL_TRY;
    }
    if (credentials[SIGN_SLOT] == 0) {
      pInfo->flags |= CKF_USER_PIN_LOCKED;
    }
    
    pInfo->ulMaxSessionCount = 10;     /* max open sessions */
    pInfo->ulSessionCount = 0;        /* sess. now open */
    pInfo->ulMaxRwSessionCount = 10;   /* max R/W sessions */
    pInfo->ulRwSessionCount = 0;      /* R/W sess. now open */
    pInfo->ulMaxPinLen = 12;           /* in bytes */
    pInfo->ulMinPinLen = 4;           /* in bytes */
    pInfo->ulTotalPublicMemory = 2048;   /* in bytes */
    pInfo->ulFreePublicMemory = 0;    /* in bytes */
    pInfo->ulTotalPrivateMemory = 2048;  /* in bytes */
    pInfo->ulFreePrivateMemory = 0;   /* in bytes */
    
    CK_VERSION nulVer = {1, 0};
    pInfo->hardwareVersion = nulVer;
    pInfo->firmwareVersion = nulVer;
    
    _log("C_GetTokenInfo returning CKR_OK");
    return CKR_OK;
  }catch(std::runtime_error &err)
  {
    _log("C_GetTokenInfo error");
    _log(err.what());
    return CKR_GENERAL_ERROR;
  }
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_GetSlotList(
                                                        CK_BBOOL tokenPresent,  /* only slots with tokens? */
                                                        CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
                                                        CK_ULONG_PTR pulCount       /* receives number of slots */
                                                        )) {
  FLOG;
  
  try {
    uint requestedSlotCount = *pulCount;
    *pulCount = 0;

    CK_SLOT_ID_PTR pSlot = pSlotList;

    int tokensCount = mgr->getTokenCount(true);
    _log("number of tokens %i", tokensCount);
    for(uint i = 0; i < tokensCount; i++) {
      _log("slot list index = %i", i);
      createCardManager(i);

      if ((tokenPresent && cardm.isInReader(i)) || !tokenPresent) {
        *pulCount += 2;
        
        if (pSlotList != NULL && *pulCount <= requestedSlotCount) {
          *pSlot++ = (i * 2);
          *pSlot++ = (i * 2) + 1;
        }
      }
    }
    FLOG
    if (pSlotList == NULL) {
      return CKR_OK;
    }
    
    if (*pulCount > requestedSlotCount) {
      _log("C_GetSlotList returning CKR_BUFFER_TOO_SMALL");
      return CKR_BUFFER_TOO_SMALL;
    }
    
    _log("C_GetSlotList returning CKR_OK");
  }
  catch(std::runtime_error &a)
  {
    _log("C_GetSlotList failed (slot count will be 0): %s", a.what());
  }
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_GetSlotInfo(
                                                        CK_SLOT_ID slotID,  /* ID of the token's slot */
                                                        CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
                                                        )) {
  FLOG;
  unsigned int readerId = slotID / 2;
  _log("readerId = %i, slotID = %i", readerId, slotID);
  
  try {
    if (checkSlot(slotID)) {
      return CKR_SLOT_ID_INVALID;
    }
    createCardManager(readerId);
    memset(pInfo, 0, sizeof(*pInfo));
    padString(pInfo->slotDescription, sizeof(pInfo->slotDescription), cardm.getReaderName().c_str());
    padString(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "EstEID");
    pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
    if (cardm.isInReader(readerId)) {
      pInfo->flags |= CKF_TOKEN_PRESENT;
    }
    CK_VERSION nulVer = {1, 0};
    pInfo->hardwareVersion = nulVer;
    pInfo->firmwareVersion = nulVer;
    _log("C_GetSlotInfo returning CKR_OK");
    return CKR_OK;
  }catch(std::runtime_error &e)
  {
    _log("C_GetSlotInfo returning CKR_GENERAL_ERROR (%s)", e.what());
    return CKR_GENERAL_ERROR;
  }
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_GetMechanismList(
                                                             CK_SLOT_ID slotID,          /* ID of token's slot */
                                                             CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
                                                             CK_ULONG_PTR pulCount         /* gets # of mechs. */
                                                             )) {
  FLOG;
  _log("slotID = %lu", slotID);
  
  CK_ULONG count = *pulCount;
  *pulCount = 1;

  if (checkSlot(slotID)) {
    return CKR_SLOT_ID_INVALID;
  }
  if (pMechanismList == NULL ) {
    return CKR_OK;
  }
  if (count < *pulCount) {
    return CKR_BUFFER_TOO_SMALL;
  }
  pMechanismList[0] = CKM_RSA_PKCS;
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_GetMechanismInfo(
                                                             CK_SLOT_ID slotID,  /* ID of the token's slot */
                                                             CK_MECHANISM_TYPE  type,    /* type of mechanism */
                                                             CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
                                                             )) {
  FLOG;
  
  pInfo->ulMinKeySize = 1024;
  pInfo->ulMaxKeySize = 2048;
  pInfo->flags = CKF_HW | CKF_ENCRYPT | CKF_SIGN | CKF_DECRYPT;
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_InitToken(
                                                      CK_SLOT_ID slotID,    /* ID of the token's slot */
                                                      CK_UTF8CHAR_PTR  pPin,      /* the SO's initial PIN */
                                                      CK_ULONG len ,  /* length in bytes of the PIN */
                                                      CK_UTF8CHAR_PTR  pLabel     /* 32-byte token label (blank padded) */
                                                      )) {
  FLOG;
  
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_OpenSession(
                                                        CK_SLOT_ID slotID,        /* the slot's ID */
                                                        CK_FLAGS flags,         /* from CK_SESSION_INFO */
                                                        CK_VOID_PTR pApplication,  /* passed to callback */
                                                        CK_NOTIFY Notify,        /* callback function */
                                                        CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
                                                        )) {
  FLOG;
  
  try {
    if (checkSlot(slotID)) {
      return CKR_SLOT_ID_INVALID;
    }
    
    if (!(flags & CKF_SERIAL_SESSION)) {
      return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    CK_SLOT_ID readerID = slotID / 2;
    createCardManager(readerID);
    if (!cardm.isInReader(readerID)){
      _log("CKR_DEVICE_REMOVED");
      return CKR_DEVICE_REMOVED;
    }

    *phSession = getNextSessionHandle();
    _log("sessionHandle = %lu, slotID = %lu", *phSession, slotID);
    sessions.push_back(PKCS11Session(*phSession, slotID, flags, pApplication, Notify));

    sessIter sessI, sess = --sessions.end();
    for (sessI = sessions.begin(); sessI != sessions.end(); sessI++) {
      if (sessI->slotID == slotID) {
        sess->state = sessI->state;
        sess->pin = sessI->pin;
        break;
      }
    }
    sess->readerID = readerID;

    if (IS_SIGN_SLOT) {
      _log("C_OpenSession, createCertificate, getSignCert, slot 1");
      sess->createCertificate(cardm.getSignCert(), sess->sign, "Signature", 223);
    } else {
      _log((slotID == 0 ? "C_OpenSession, createCertificate, getAuthCert, slot 0" : "C_OpenSession, createCertificate, getAuthCert, unknown slot"));
      sess->createCertificate(cardm.getAuthCert(), sess->auth, "Authentication", 123);
    }
    return CKR_OK;
  }
  catch(std::runtime_error &)
  {
    _log("CKR_GENERAL_ERROR");
    return CKR_GENERAL_ERROR;
  }
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_GetSessionInfo(
                                                           CK_SESSION_HANDLE hSession,
                                                           CK_SESSION_INFO_PTR pInfo)) {
  FLOG;

  _log("SESSIONS SIZE = %i", sessions.size());
  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  FLOG;
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  FLOG;
  pInfo->slotID = sess->slotID;
  pInfo->state = sess->state;
  pInfo->flags = sess->flags;
  pInfo->ulDeviceError = 0;
  FLOG;
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_CloseSession(CK_SESSION_HANDLE hSession)) {
  FLOG;
  sessions.erase(std::remove_if(sessions.begin(), sessions.end(), [&](PKCS11Session &session ){ return session.session == hSession;}), sessions.end());
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_CloseAllSessions(CK_SLOT_ID slotID)) {
  FLOG;
  sessions.erase(std::remove_if(sessions.begin(), sessions.end(), [&](PKCS11Session &session ){ return session.slotID == slotID;}), sessions.end());
  return CKR_OK;
}

class searchTerm {
  std::vector<CK_ATTRIBUTE > param;
  CK_ULONG mState; //public/private
  friend class PKCS11Object;
  
public:
  searchTerm(std::vector<CK_ATTRIBUTE > searchParam, CK_ULONG state) :
  param(searchParam), mState(state) {
    FLOG
  }
  
  bool operator ()(const PKCS11Object& value) {
    std::vector<CK_ATTRIBUTE >::const_iterator objAtt;
    if (mState == CKS_RO_PUBLIC_SESSION) {//check if CK_PRIVATE is set
      objAtt = find(value.attrib.begin(), value.attrib.end(), CKA_PRIVATE);
      if (objAtt != value.attrib.end()){ //private was found
        return true;
      }
    }
    for (attrIter att = param.begin(); att != param.end(); att++) {
      objAtt = find(value.attrib.begin(), value.attrib.end(), att->type);
      
      if (value.attrib.end() == objAtt){ //object does not have required attribute
        return true;
      }
      if (memcmp(objAtt->pValue, att->pValue, std::min(objAtt->ulValueLen, att->ulValueLen))) {
        _log("-------- has attribute but does not match");
        return true;
      }
    }
    _log("-------- found object");
    return false;
  }
  
  bool operator ()(const ObjHandle& value) {
    FLOG
    return true;
  }
};

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_FindObjectsInit(
                                                            CK_SESSION_HANDLE hSession,   /* the session's handle */
                                                            CK_ATTRIBUTE_PTR pTemplate,  /* attribute values to match */
                                                            CK_ULONG ulCount     /* attrs in search template */
                                                            )) {
  FLOG;
  
  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  sess->searchParam.clear();
  
  for (uint i = 0; i < ulCount; i++){
    sess->searchParam.push_back(*(pTemplate + i));
  }
  
  sess->searchHandles.clear();
  sess->searchHandles.resize(sess->objects.size());
  std::vector<ObjHandle >::iterator copy = remove_copy_if(sess->objects.begin(),
                                                          sess->objects.end(),
                                                          sess->searchHandles.begin(),
                                                          searchTerm(sess->searchParam, sess->state));

  sess->searchHandles.resize(copy - sess->searchHandles.begin());
  
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_FindObjects(
                                                        CK_SESSION_HANDLE hSession,          /* session's handle */
                                                        CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
                                                        CK_ULONG ulMaxObjectCount,  /* max handles to get */
                                                        CK_ULONG_PTR pulObjectCount     /* actual # returned */
                                                        )) {
  FLOG;
  
  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  
  CK_ULONG returnCount = std::min(ulMaxObjectCount, (CK_ULONG) sess->searchHandles.size());
  *pulObjectCount = returnCount;
  
  if (returnCount) {
    memcpy(phObject, &sess->searchHandles.front(), returnCount * sizeof(CK_OBJECT_HANDLE));
  }
  
  sess->searchHandles.erase(sess->searchHandles.begin(), sess->searchHandles.end());
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_FindObjectsFinal(
                                                             CK_SESSION_HANDLE
                                                             hSession  /* the session's handle */
                                                             )) {
  FLOG;
  
  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  sess->searchParam.clear();
  sess->searchHandles.clear();
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_Login(CK_SESSION_HANDLE hSession,  /* the session's handle */
                                                  CK_USER_TYPE userType,       /* the user type */
                                                  CK_UTF8CHAR_PTR pPin,        /* the user's PIN */
                                                  CK_ULONG ulPinLen            /* the length of the PIN */
                                                  )) {
  FLOG;
  
  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  
  sess->pin = PinString((const char *) pPin, (size_t) ulPinLen);
  
  try {
    createCardManager(sess->readerID);
    if (!cardm.isInReader(sess->readerID)){
      _log("CKR_DEVICE_REMOVED");
      return CKR_DEVICE_REMOVED;
    }
    _log("slotId = %i, sess->readerID = %i, user = %ul", sess->slotID, sess->readerID, userType);

    byte retriesLeft;
    if (sess->IS_SIGN_SLOT) {
      FLOG;
      cardm.validateSignPin(sess->pin, retriesLeft);
    }
    else {
      FLOG;
      cardm.validateAuthPin(sess->pin, retriesLeft);
    }
  } catch ( AuthError &ae) {
    if (ae.m_badinput)  {
      return CKR_PIN_LEN_RANGE;
    }
    else if (ae.m_aborted) {
      return CKR_FUNCTION_CANCELED;
    }
    else {
      return CKR_PIN_INCORRECT;
    }
  } catch( std::runtime_error &err) {
    _log("CKR_GENERAL_ERROR");
    return CKR_GENERAL_ERROR;
  }

  for_each(sessions.begin(), sessions.end(),  PKCS11Session::changeState(sess->slotID, CKS_RO_USER_FUNCTIONS, sess->pin));
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, PKCS11Context::C_Logout(CK_SESSION_HANDLE hSession  /* the session's handle */ )) {
  FLOG;
  
  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  for_each(sessions.begin(), sessions.end(), PKCS11Session::changeState(sess->slotID, CKS_RO_PUBLIC_SESSION, sess->pin));
  sess->pin.clear();
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_GetAttributeValue(
                                                              CK_SESSION_HANDLE hSession,   /* the session's handle */
                                                              CK_OBJECT_HANDLE hObject,    /* the object's handle */
                                                              CK_ATTRIBUTE_PTR pTemplate,  /* specifies attrs; gets vals */
                                                              CK_ULONG ulCount     /* attributes in template */
                                                              )) {
  FLOG;
  
  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  
  objectIter obj = find(sess->objects.begin(), sess->objects.end(), ObjHandle(hObject));
  
  if (obj == sess->objects.end()) {
    return CKR_OBJECT_HANDLE_INVALID;
  }
  
  bool invalidAttributeExists = false;
  for (uint i = 0; i < ulCount; i++) {
    CK_ATTRIBUTE_PTR attrib = pTemplate + i;
    _log("------------ Attribute to search:%X, sessionHandle = %lu", attrib->type, hSession);
    attrIter objAttrib = obj->findAttrib(attrib);
    attrib->ulValueLen = -1;
    
    if (obj->noAttrib(objAttrib)) {
      _log("Attribute not found");
      invalidAttributeExists = true;
      continue;
    }
    
    if (attrib->pValue == NULL) {
      _log("value is NULL. Continue");
      attrib->ulValueLen = objAttrib->ulValueLen;
      continue;
    }
    if (attrib->ulValueLen >= objAttrib->ulValueLen) {
      memcpy(attrib->pValue, objAttrib->pValue, std::min(attrib->ulValueLen, objAttrib->ulValueLen));
      attrib->ulValueLen = objAttrib->ulValueLen;
      _log("Attribute found.");
      continue;
    }
  }
  FLOG
  return (CK_RV) ( invalidAttributeExists ? CKR_ATTRIBUTE_TYPE_INVALID : CKR_OK);
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_SignInit(
                                                     CK_SESSION_HANDLE hSession,    /* the session's handle */
                                                     CK_MECHANISM_PTR pMechanism,  /* the signature mechanism */
                                                     CK_OBJECT_HANDLE hKey )) {    /* handle of signature key */
  FLOG;
  
  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  if (sess->state != CKS_RO_USER_FUNCTIONS) {
    return CKR_USER_NOT_LOGGED_IN;
  }

  memcpy(&sess->sigMechanism, pMechanism, sizeof(*pMechanism));
  switch (sess->sigMechanism.mechanism) {
    case CKM_RSA_PKCS:
      return CKR_OK;
    default:
      return CKR_MECHANISM_INVALID;
  }
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_SignUpdate(
                                                       CK_SESSION_HANDLE hSession,  /* the session's handle */
                                                       CK_BYTE_PTR pPart,     /* the data to sign */
                                                       CK_ULONG ulPartLen )) {/* count of bytes to sign */
  FLOG;
  
  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  if (sess->state != CKS_RO_USER_FUNCTIONS) {
    return CKR_USER_NOT_LOGGED_IN;
  }

  sess->dataToSign.insert(sess->dataToSign.end(), pPart, pPart + ulPartLen);
  
  return CKR_OK;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_Sign(
                                                 CK_SESSION_HANDLE hSession,        /* the session's handle */
                                                 CK_BYTE_PTR pData,           /* the data to sign */
                                                 CK_ULONG ulDataLen,       /* count of bytes to sign */
                                                 CK_BYTE_PTR pSignature,      /* gets the signature */
                                                 CK_ULONG_PTR pulSignatureLen )) {/* gets signature length */
  FLOG;

  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  if (sess->state != CKS_RO_USER_FUNCTIONS) {
    return CKR_USER_NOT_LOGGED_IN;
  }
  try {
    CK_ULONG len = *pulSignatureLen;

    createCardManager(sess->readerID);
    if (!cardm.isInReader(sess->readerID)) {
      return CKR_DEVICE_REMOVED;
    }
    *pulSignatureLen = cardm.getKeySize() / 8;
    if (pSignature == NULL) {
      return CKR_OK;
    }
    if (len < *pulSignatureLen) {
      return CKR_BUFFER_TOO_SMALL;
    }
    ByteVec input(pData, pData + ulDataLen);
    ByteVec result = signData(input, sess);
    if (result.size() == 0) {
      _log("Signature length invalid (0). Returning CKR_FUNCTION_FAILED");
      return CKR_FUNCTION_FAILED;
    }
    memcpy(pSignature, &result[0], result.size());
    memset(&sess->sigMechanism, 0, sizeof(sess->sigMechanism));
    return CKR_OK;
  } catch ( AuthError &ae ) {
    _log("SIGNERROR = %s", ae.what());
    return CKR_FUNCTION_CANCELED;
  } catch ( CardError &ce ) {
    _log("SIGNERROR = %s", ce.what());
    return CKR_FUNCTION_FAILED;
  } catch ( CardResetError &ce ) {
    _log("RESETERROR = %s", ce.what());
    return CKR_FUNCTION_FAILED;
  } catch ( std::runtime_error &err ) {
    _log("SIGNERROR = %s", err.what());
    return CKR_GENERAL_ERROR;
  }
}


ByteVec PKCS11Context::signData(ByteVec const & dataToSign, std::vector<PKCS11Session>::iterator session) {
  ByteVec  result;

  createCardManager(session->readerID);
  EstEIDManager::KeyType key = session->IS_SIGN_SLOT ? EstEIDManager::SIGN : EstEIDManager::AUTH;
  if (session->sigMechanism.mechanism == CKM_RSA_PKCS) {
    result = cardm.sign(dataToSign, EstEIDManager::SSL, key, session->pin);
  }
  return result;
}

CK_DECLARE_FUNCTION (CK_RV, PKCS11Context::C_SignFinal(
                                                       CK_SESSION_HANDLE hSession,        /* the session's handle */
                                                       CK_BYTE_PTR pSignature,      /* gets the signature */
                                                       CK_ULONG_PTR pulSignatureLen )) { /* gets signature length */
  FLOG;


  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }

  CK_BYTE_PTR pData = sess->dataToSign.size() == 0 ? NULL_PTR : &sess->dataToSign[0];
  CK_RV result = PKCS11Context::C_Sign(hSession, pData, sess->dataToSign.size(), pSignature, pulSignatureLen);
  if (pSignature != NULL_PTR) {
    sess->dataToSign.clear();
  }
  return result;
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)) {
  FLOG
  return PKCS11Context::C_SignInit(hSession, pMechanism, hKey);
}

CK_DECLARE_FUNCTION(CK_RV, PKCS11Context::C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)) {
  _log("enc = %i, data = %i", ulEncryptedDataLen, *pulDataLen);
  
  sessIter sess = find(sessions.begin(), sessions.end(), hSession);
  if (sessions.end() == sess) {
    return CKR_SESSION_HANDLE_INVALID;
  }
  if (sess->state != CKS_RO_USER_FUNCTIONS) {
    return CKR_USER_NOT_LOGGED_IN;
  }
  
  ByteVec cipher(pEncryptedData, pEncryptedData + ulEncryptedDataLen);
  createCardManager(sess->readerID);
  ByteVec decryptedData = cardm.RSADecrypt(cipher, sess->pin);

  if (decryptedData.size() == 0) {
    _log("Decrypted data length invalid (0). Returning CKR_FUNCTION_FAILED");
    return CKR_FUNCTION_FAILED;
  }

  *pulDataLen = decryptedData.size();
  if (pData == NULL) {
    return CKR_OK;
  }
  memcpy(pData, &decryptedData[0], decryptedData.size());
  
  return CKR_OK;
}

