#include "gmock/gmock.h"
#include "PKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;
using namespace std;

TEST(PKCS11Context, C_Login_NoSession) {
  MockCardManager manager;
  PKCS11Context context(&manager);

  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_Login(0, 0, NULL, 4));
}

TEST(PKCS11Context, C_Login_CardRemoved) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(true)).WillOnce(Return(false));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillOnce(Return(*cert));

  CK_SESSION_HANDLE sessionHandle;
  PKCS11Context context(&manager);

  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionHandle));
  ASSERT_EQ(CKR_DEVICE_REMOVED, context.C_Login(sessionHandle, 0, (unsigned char*)"", 4));

  delete cert;
}

TEST(PKCS11Context, C_Login_WithRuntimeException) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(true)).WillOnce(Throw(std::runtime_error("")));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillOnce(Return(*cert));

  CK_SESSION_HANDLE sessionHandle;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionHandle));
  ASSERT_EQ(CKR_GENERAL_ERROR, context.C_Login(sessionHandle, 0, (unsigned char*)"", 4));

  delete cert;
}

TEST(PKCS11Context, C_Login_WrongPin) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getAuthCert()).WillOnce(Return(*cert));
  EXPECT_CALL(manager, validateAuthPin(_,_)).WillOnce(Throw(AuthError(0,0)));

  CK_SESSION_HANDLE sessionHandle;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionHandle));
  ASSERT_EQ(CKR_PIN_INCORRECT, context.C_Login(sessionHandle, 0, (unsigned char*)"", 4));

  delete cert;
}

TEST(PKCS11Context, C_Login_WrongPinLength) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getAuthCert()).WillOnce(Return(*cert));
  AuthError error(0,0);
  error.m_badinput = true;
  EXPECT_CALL(manager, validateAuthPin(_,_)).WillOnce(Throw(error));

  CK_SESSION_HANDLE sessionHandle;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionHandle));
  ASSERT_EQ(CKR_PIN_LEN_RANGE, context.C_Login(sessionHandle, 0, (unsigned char*)"", 4));

  delete cert;
}

TEST(PKCS11Context, C_Login_PinEnteringAborted) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getAuthCert()).WillOnce(Return(*cert));
  AuthError error(0,0);
  error.m_aborted = true;
  EXPECT_CALL(manager, validateAuthPin(_,_)).WillOnce(Throw(error));

  CK_SESSION_HANDLE sessionHandle;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionHandle));
  ASSERT_EQ(CKR_FUNCTION_CANCELED, context.C_Login(sessionHandle, 0, (unsigned char*)"", 4));

  delete cert;
}

TEST(PKCS11Context, C_Login) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  unsigned char pin[] = "1234";
  PinString pinString((const char *)pin, (size_t)4);
  EXPECT_CALL(manager, validateSignPin(pinString,_));

  CK_SESSION_HANDLE sessionHandle_one;
  CK_SESSION_HANDLE sessionHandle_two;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionHandle_one));
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionHandle_two));
  ASSERT_EQ(CKR_OK, context.C_Login(sessionHandle_one, 0, pin, 4));

  CK_SESSION_INFO pInfo;
  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_one, &pInfo));
  ASSERT_EQ(CKS_RO_USER_FUNCTIONS, pInfo.state);

  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_two, &pInfo));
  ASSERT_EQ(CKS_RO_USER_FUNCTIONS, pInfo.state);

  ASSERT_EQ(CKR_OK, context.C_Logout(sessionHandle_one));

  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_one, &pInfo));
  ASSERT_EQ(CKS_RO_PUBLIC_SESSION, pInfo.state);

  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_two, &pInfo));
  ASSERT_EQ(CKS_RO_PUBLIC_SESSION, pInfo.state);

  context.C_CloseAllSessions(1);

  delete cert;
}

TEST(PKCS11Context, C_Logout_InvalisSessionHandle) {
  MockCardManager manager;

  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_Logout(304));
}
