#include "gmock/gmock.h"
#include <CardManager.h>

char* nullTerminatedString(char*, unsigned char *, size_t );
unsigned char *hex2bin(const char *);
ByteVec *getCert();

class MockCardManager : public CardManager {
public:
  MOCK_METHOD1(getTokenCount, unsigned int(bool forceRefresh));
  MOCK_METHOD1(isInReader, bool(unsigned int idx));
  MOCK_METHOD0(isSecureConnection, bool());
  MOCK_METHOD0(isDigiID, bool());
  MOCK_METHOD1(readCardName, std::string(bool firstNameFirst));
  MOCK_METHOD3(getRetryCounts, bool(byte &puk, byte &pinAuth, byte &pinSign));
  MOCK_METHOD0(getAuthCert, ByteVec());
  MOCK_METHOD0(getSignCert, ByteVec());
  MOCK_METHOD0(getKeySize, unsigned int());
  MOCK_METHOD2(validateAuthPin, void(const PinString &, byte &));
  MOCK_METHOD2(validateSignPin, void(const PinString &, byte &));
  MOCK_METHOD4(sign, ByteVec(const ByteVec &, EstEIDManager::AlgType, EstEIDManager::KeyType, const PinString &));
  MOCK_METHOD2(RSADecrypt, ByteVec(const ByteVec &cipher, const PinString &pin));
};


