#include "gmock/gmock.h"
#include "PKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;
using namespace std;

TEST(PKCS11Context, C_Decrypt_InvalidSession) {
  MockCardManager manager;
  PKCS11Context context(&manager);

  CK_ULONG pulDataLen = 0;
  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_Decrypt(101, NULL_PTR, 0, NULL_PTR, &pulDataLen));
}

TEST(PKCS11Context, C_Decrypt_UserNotLoggedIn) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));

  CK_ULONG pulDataLen = 0;
  ASSERT_EQ(CKR_USER_NOT_LOGGED_IN, context.C_Decrypt(session, NULL_PTR, 0, NULL_PTR, &pulDataLen));

  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_Decrypt_FunctionFailed) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));
  EXPECT_CALL(manager, RSADecrypt(_,_)).WillOnce(Return(ByteVec()));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)"0000", 4));

  CK_ULONG plaintextLen = 0;
  ASSERT_EQ(CKR_FUNCTION_FAILED, context.C_Decrypt(session, NULL_PTR, 0, NULL_PTR, &plaintextLen));

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_Decrypt) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));
  CK_BYTE encryptedDataArray[] = {'0x59', '0x60', '0x45', '0x55'};
  ByteVec encryptedData = ByteVec(encryptedDataArray, encryptedDataArray + 4);
  unsigned char pin[] = "1234";
  size_t pinLength = 4;
  PinString pinString((const char *)pin, pinLength);
  CK_BYTE expectedPlaintextArray[] = {'A', 'B', 'C', 'D'};
  ByteVec expectedPlaintext = ByteVec(expectedPlaintextArray, expectedPlaintextArray + 4);
  EXPECT_CALL(manager, RSADecrypt(encryptedData, pinString)).WillRepeatedly(Return(expectedPlaintext));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)pin, pinLength));

  CK_ULONG plaintextLen = 0;
  ASSERT_EQ(CKR_OK, context.C_Decrypt(session, encryptedDataArray, 4, NULL_PTR, &plaintextLen));

  CK_BYTE_PTR plaintext = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE) * plaintextLen);
  ASSERT_EQ(CKR_OK, context.C_Decrypt(session, encryptedDataArray, 4, plaintext, &plaintextLen));
  ASSERT_EQ(*expectedPlaintextArray, *plaintext);

  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}