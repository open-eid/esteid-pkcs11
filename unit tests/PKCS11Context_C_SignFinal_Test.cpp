#include "gmock/gmock.h"
#include "PKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;
using namespace std;

TEST(PKCS11Context, C_SignUpdate_InvalidSession) {
  MockCardManager manager;
  PKCS11Context context(&manager);

  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_SignUpdate(101, NULL_PTR, 0));
}

TEST(PKCS11Context, C_SignUpdate_UserNotLoggedIn) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));

  ASSERT_EQ(CKR_USER_NOT_LOGGED_IN, context.C_SignUpdate(session, NULL_PTR, 0));

  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_SignFinal_InvalidSession) {
  MockCardManager manager;
  PKCS11Context context(&manager);

  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_SignFinal(101, NULL_PTR, 0));
}

TEST(PKCS11Context, C_SignFinal_UserNotLoggedIn) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));

  ASSERT_EQ(CKR_USER_NOT_LOGGED_IN, context.C_SignFinal(session, NULL_PTR, 0));

  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_SignFinal_CardRemoved) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(true)).WillOnce(Return(true)).WillOnce(Return(false));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)"0000", 4));

  CK_ULONG signatureLen;
  ASSERT_EQ(CKR_DEVICE_REMOVED, context.C_SignFinal(session, NULL_PTR, &signatureLen));

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_SignFinal_BufferToSmall) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));
  EXPECT_CALL(manager, getKeySize()).WillRepeatedly(Return(1024));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)"0000", 4));

  CK_ULONG signatureLen = 1;
  CK_BYTE signature[3];
  ASSERT_EQ(CKR_BUFFER_TOO_SMALL, context.C_SignFinal(session, signature, &signatureLen));

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_SignFinal_FunctionFailed) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));
  EXPECT_CALL(manager, getKeySize()).WillRepeatedly(Return(1024));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)"0000", 4));

  CK_ULONG signatureLen = 128;
  CK_BYTE signature[128];
  ASSERT_EQ(CKR_FUNCTION_FAILED, context.C_SignFinal(session, signature, &signatureLen));

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_SignFinal_GeneralError) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(true)).WillOnce(Return(true)).WillOnce(Throw(std::runtime_error("")));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));
  EXPECT_CALL(manager, getKeySize()).WillRepeatedly(Return(1024));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)"0000", 4));

  CK_ULONG signatureLen = 128;
  CK_BYTE signature[128];
  ASSERT_EQ(CKR_GENERAL_ERROR, context.C_SignFinal(session, signature, &signatureLen));

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_SignFinal_CardResetError) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(true)).WillOnce(Return(true)).WillOnce(Throw(CardResetError()));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));
  EXPECT_CALL(manager, getKeySize()).WillRepeatedly(Return(1024));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)"0000", 4));

  CK_ULONG signatureLen = 128;
  CK_BYTE signature[128];
  ASSERT_EQ(CKR_FUNCTION_FAILED, context.C_SignFinal(session, signature, &signatureLen));

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_SignFinal_CardError) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(true)).WillOnce(Return(true)).WillOnce(Throw(CardError(0, 0)));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));
  EXPECT_CALL(manager, getKeySize()).WillRepeatedly(Return(1024));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)"0000", 4));

  CK_ULONG signatureLen = 128;
  CK_BYTE signature[128];
  ASSERT_EQ(CKR_FUNCTION_FAILED, context.C_SignFinal(session, signature, &signatureLen));

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_SignFinal_FunctionCancelled) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(true)).WillOnce(Return(true)).WillOnce(Throw(AuthError(0, 0)));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));
  EXPECT_CALL(manager, getKeySize()).WillRepeatedly(Return(1024));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)"0000", 4));

  CK_ULONG signatureLen = 128;
  CK_BYTE signature[128];
  ASSERT_EQ(CKR_FUNCTION_CANCELED, context.C_SignFinal(session, signature, &signatureLen));

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_SignFinal_AuthSlot) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getAuthCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateAuthPin(_,_));
  byte expectedSignatureArray[] = {'0x30', '0x31', '0x32', '0x33'};
  ByteVec expectedSignature(expectedSignatureArray, expectedSignatureArray + 4);
  EXPECT_CALL(manager, getKeySize()).WillRepeatedly(Return(expectedSignature.size()));
  byte dataToSignArray[] = {'0x40', '0x41', '0x42', '0x43', '0x44'};
  ByteVec dataToSign(dataToSignArray, dataToSignArray + 5);
  unsigned char pin[] = "1234";
  size_t pinLength = 4;
  PinString pinString((const char *)pin, pinLength);
  EXPECT_CALL(manager, sign(dataToSign, EstEIDManager::SSL, EstEIDManager::AUTH, pinString)).WillRepeatedly(Return(expectedSignature));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, pin, pinLength));

  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_RSA_PKCS;
  ASSERT_EQ(CKR_OK, context.C_SignInit(session, &mechanism, NULL_PTR));

  ASSERT_EQ(CKR_OK, context.C_SignUpdate(session, dataToSignArray, 2));
  ASSERT_EQ(CKR_OK, context.C_SignUpdate(session, dataToSignArray + 2, 3));

  CK_ULONG signatureLen = 0;
  ASSERT_EQ(CKR_OK, context.C_SignFinal(session, NULL_PTR, &signatureLen));

  CK_BYTE_PTR signature = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE) * signatureLen);
  ASSERT_EQ(CKR_OK, context.C_SignFinal(session, signature, &signatureLen));
  ASSERT_EQ(*expectedSignatureArray, *signature);

  //call C_SignFinal again to verify that session will be cleared after successful sign
  ASSERT_EQ(CKR_FUNCTION_FAILED, context.C_SignFinal(session, signature, &signatureLen));

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  free(signature);
  delete cert;
}

TEST(PKCS11Context, C_SignFinal_SignSlot) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));
  byte expectedSignatureArray[] = {'0x30', '0x31', '0x32', '0x33'};
  ByteVec expectedSignature(expectedSignatureArray, expectedSignatureArray + 4);
  EXPECT_CALL(manager, getKeySize()).WillRepeatedly(Return(expectedSignature.size()));
  byte dataToSignArray[] = {'0x40', '0x41', '0x42', '0x43', '0x44'};
  ByteVec dataToSign(dataToSignArray, dataToSignArray + 5);
  unsigned char pin[] = "1234";
  size_t pinLength = 4;
  PinString pinString((const char *)pin, pinLength);
  EXPECT_CALL(manager, sign(dataToSign, EstEIDManager::SSL, EstEIDManager::SIGN, pinString)).WillRepeatedly(Return(expectedSignature));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, pin, pinLength));

  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_RSA_PKCS;
  ASSERT_EQ(CKR_OK, context.C_SignInit(session, &mechanism, NULL_PTR));

  ASSERT_EQ(CKR_OK, context.C_SignUpdate(session, dataToSignArray, 2));
  ASSERT_EQ(CKR_OK, context.C_SignUpdate(session, dataToSignArray + 2, 3));

  CK_ULONG signatureLen = 0;
  ASSERT_EQ(CKR_OK, context.C_SignFinal(session, NULL_PTR, &signatureLen));

  CK_BYTE_PTR signature = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE) * signatureLen);
  ASSERT_EQ(CKR_OK, context.C_SignFinal(session, signature, &signatureLen));
  ASSERT_EQ(*expectedSignatureArray, *signature);

  //call C_SignFinal again to verify that session will be cleared after successful sign
  ASSERT_EQ(CKR_FUNCTION_FAILED, context.C_SignFinal(session, signature, &signatureLen));

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  free(signature);
  delete cert;
}
