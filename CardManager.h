#ifndef __EstEIDTestManager_H_
#define __EstEIDTestManager_H_

#include "smartcardpp/EstEIDManager.h"

using namespace std;

class CardManager {
public:
  CardManager() {};
  CardManager(int readerId) {};
  virtual ~CardManager() {};

  virtual bool isInReader(unsigned int idx) {return false;}
  virtual string readCardID() {return "37101010021";}
  virtual string readDocumentID() {return "X0010119";}
  virtual string readCardName(bool firstNameFirst = false) {return "Igor Žaikovski";}
  virtual bool isDigiID() {return false;}
  virtual bool isSecureConnection() {return false;}
  virtual bool getRetryCounts(byte &puk,byte &pinAuth,byte &pinSign) {return false;}
  virtual ByteVec getAuthCert() {return ByteVec();}
  virtual ByteVec getSignCert() {return ByteVec();}
  virtual ByteVec RSADecrypt(const ByteVec &cipher, const PinString &pin) {return ByteVec();}
  virtual string getReaderName() {return "OMNIKEY 1021";}
  virtual unsigned int getTokenCount(bool forceRefresh) {return 0;}
  virtual void validateSignPin(const PinString &, byte &) {}
  virtual void validateAuthPin(const PinString &, byte &) {}
  virtual unsigned int getKeySize() {return 1024;}
  virtual ByteVec sign(const ByteVec &hash, EstEIDManager::AlgType type, EstEIDManager::KeyType keyId, const PinString &pin) { return ByteVec();}

};
#endif //__EstEIDTestManager_H_
