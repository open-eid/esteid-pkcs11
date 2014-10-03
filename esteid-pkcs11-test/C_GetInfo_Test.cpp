#include <pkcs11.h>
#include <stdlib.h>
#include "esteid-pkcs11-test.h"
#include <gmock/gmock.h>

using namespace std;

TEST(CardTest, C_GetInfo) {
  CK_INFO_PTR pInfo = (CK_INFO_PTR) malloc(sizeof(CK_INFO));
  ASSERT_EQ(CKR_OK, fl->C_GetInfo(pInfo));
  free(pInfo);
}

TEST(CardTest, C_GetSlotInfo) {
  CK_ULONG pulCount;
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, NULL_PTR, &pulCount));

  //TODO: what to do if no cards where found?

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR) malloc(pulCount * sizeof(unsigned long));
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, pSlotList, &pulCount));

  CK_SLOT_INFO_PTR pInfo = (CK_SLOT_INFO_PTR) malloc(sizeof(CK_SLOT_INFO));
  ASSERT_EQ(CKR_OK, fl->C_GetSlotInfo(slotId, pInfo));

  CK_FLAGS flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT | CKF_TOKEN_PRESENT;
  ASSERT_EQ(flags, pInfo->flags);

  char description[65];
  ASSERT_STREQ(config["slotInfo.readerName"].c_str(), nullTerminatedString(description, pInfo->slotDescription, 64));
}

TEST(CardTest, getAuthenticationTokenInfo) {
  CK_ULONG pulCount;
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, NULL_PTR, &pulCount));

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR) malloc(pulCount * sizeof(unsigned long));
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, pSlotList, &pulCount));

  CK_TOKEN_INFO pInfo;
  ASSERT_EQ(CKR_OK, fl->C_GetTokenInfo(slotId, &pInfo));

  char result[33];

  ASSERT_EQ(config["tokenInfo.authLabel"], string(nullTerminatedString(result, pInfo.label, 32)));
  ASSERT_STREQ("EstEid smartcardpp              ", nullTerminatedString(result, pInfo.manufacturerID, 32));
  ASSERT_STREQ("original        ", nullTerminatedString(result, pInfo.model, 16));
  ASSERT_STREQ(config["tokenInfo.serialNumber"].c_str(), nullTerminatedString(result, pInfo.serialNumber, 16));
}

TEST(CardTest, getSignTokenInfo) {
  CK_ULONG pulCount;
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, NULL_PTR, &pulCount));

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR) malloc(pulCount * sizeof(unsigned long));
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, pSlotList, &pulCount));

  CK_TOKEN_INFO pInfo;
  ASSERT_EQ(CKR_OK, fl->C_GetTokenInfo(slotId+1, &pInfo));

  char result[33];
  ASSERT_EQ(config["tokenInfo.signLabel"], string(nullTerminatedString(result, pInfo.label, 32)));
}

TEST(CardTest, Client_Sign) {
  CK_ULONG pulCount;
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, NULL_PTR, &pulCount));

  CK_SLOT_ID pSlotList[pulCount];
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, pSlotList, &pulCount));

  CK_SESSION_HANDLE session;
  CK_FLAGS flags = CKF_SERIAL_SESSION;
  ASSERT_EQ(CKR_OK, fl->C_OpenSession(slotId + 1, flags, 0, 0, &session));

  ASSERT_EQ(CKR_OK, fl->C_Login(session, 0, (unsigned char*)config["sign.pin"].c_str(), config["sign.pin"].length()));

  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_RSA_PKCS;
  ASSERT_EQ(CKR_OK, fl->C_SignInit(session, &mechanism, 0));

  CK_ULONG signatureLength;
  std::string hashAsHex = config["sign.hash"].c_str();
  CK_BYTE_PTR hash = hex2bin(hashAsHex.c_str());
  ASSERT_EQ(CKR_OK, fl->C_Sign(session, hash, hashAsHex.length() / 2, NULL_PTR, &signatureLength));

  CK_BYTE signature[signatureLength];
  ASSERT_EQ(CKR_OK, fl->C_Sign(session, hash, hashAsHex.length() / 2, signature, &signatureLength));
  free(hash);

  CK_BYTE_PTR expectedSignature = hex2bin(config["sign.signature"].c_str());
  ASSERT_EQ(0, memcmp(expectedSignature, signature, (size_t)signatureLength));
  free(expectedSignature);

  ASSERT_EQ(CKR_OK, fl->C_CloseSession(session));
}

TEST(CardTest, MultipartSign) {
  CK_ULONG pulCount;
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, NULL_PTR, &pulCount));

  CK_SLOT_ID pSlotList[pulCount];
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, pSlotList, &pulCount));

  CK_SESSION_HANDLE session;
  CK_FLAGS flags = CKF_SERIAL_SESSION;
  ASSERT_EQ(CKR_OK, fl->C_OpenSession(slotId + 1, flags, 0, 0, &session));

  ASSERT_EQ(CKR_OK, fl->C_Login(session, 0, (unsigned char*)config["sign.pin"].c_str(), config["sign.pin"].length()));

  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_RSA_PKCS;
  ASSERT_EQ(CKR_OK, fl->C_SignInit(session, &mechanism, 0));

  std::string hashAsHex = config["sign.hash"].c_str();
  CK_BYTE_PTR hash = hex2bin(hashAsHex.c_str());
  size_t hashLength = hashAsHex.length() / 2;
  ASSERT_EQ(CKR_OK, fl->C_SignUpdate(session, hash, 10));
  ASSERT_EQ(CKR_OK, fl->C_SignUpdate(session, hash + 10, hashLength - 10));

  CK_ULONG signatureLength;
  ASSERT_EQ(CKR_OK, fl->C_SignFinal(session, NULL_PTR, &signatureLength));

  CK_BYTE signature[signatureLength];
  ASSERT_EQ(CKR_OK, fl->C_SignFinal(session, signature, &signatureLength));
  free(hash);

  CK_BYTE_PTR expectedSignature = hex2bin(config["sign.signature"].c_str());
  ASSERT_EQ(0, memcmp(expectedSignature, signature, (size_t)signatureLength));
  free(expectedSignature);

  ASSERT_EQ(CKR_OK, fl->C_CloseSession(session));
}

TEST(CardTest, Decrypt) {
  std::string encryptedData = config["decrypt.encryptedData"].c_str();

  CK_BYTE_PTR cipher = hex2bin(encryptedData.c_str());

  CK_ULONG pulCount;
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, NULL_PTR, &pulCount));

  CK_SLOT_ID pSlotList[pulCount];
  ASSERT_EQ(CKR_OK, fl->C_GetSlotList(CK_TRUE, pSlotList, &pulCount));

  CK_SESSION_HANDLE session;
  CK_FLAGS flags = CKF_SERIAL_SESSION;
  ASSERT_EQ(CKR_OK, fl->C_OpenSession(slotId, flags, 0, 0, &session));

  ASSERT_EQ(CKR_OK, fl->C_Login(session, 0, (unsigned char*)config["decrypt.pin"].c_str(), config["decrypt.pin"].length()));

  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_RSA_PKCS;
  ASSERT_EQ(CKR_OK, fl->C_DecryptInit(session, &mechanism, 0));

  CK_ULONG decryptedDataLength;
  ASSERT_EQ(CKR_OK,fl->C_Decrypt(session, cipher, encryptedData.length()/2, NULL_PTR, &decryptedDataLength));

  CK_BYTE decryptedData[decryptedDataLength];
  ASSERT_EQ(CKR_OK,fl->C_Decrypt(session, cipher, encryptedData.length()/2, decryptedData, &decryptedDataLength));

  char result[decryptedDataLength + 1];
  ASSERT_STREQ(config["decrypt.plainText"].c_str(), nullTerminatedString(result, decryptedData, decryptedDataLength));

}
