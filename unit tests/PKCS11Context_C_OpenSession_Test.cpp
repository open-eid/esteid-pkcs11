#include "gmock/gmock.h"
#include "PKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;
using namespace std;

TEST(PKCS11Context, C_OpenSession_InvalidSlot) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));

  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_SLOT_ID_INVALID, context.C_OpenSession(2, 0, NULL_PTR, NULL_PTR, NULL_PTR));
}

TEST(PKCS11Context, C_OpenSession_CardRemoved) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(false));
  PKCS11Context context(&manager);

  ASSERT_EQ(CKR_DEVICE_REMOVED, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, NULL));
}


TEST(PKCS11Context, C_OpenSession_ParallelSessionNotSupported) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));

  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_SESSION_PARALLEL_NOT_SUPPORTED, context.C_OpenSession(1, 0, NULL_PTR, NULL_PTR, NULL_PTR));
}

TEST(PKCS11Context, C_OpenSession_WithException) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Throw(std::runtime_error("")));

  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_GENERAL_ERROR, context.C_OpenSession(1, 0, NULL_PTR, NULL_PTR, NULL_PTR));
}

TEST(PKCS11Context, C_OpenSession_WithSeveralSessions) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));

  CK_SESSION_HANDLE sessionHandle_one;
  CK_SESSION_HANDLE sessionHandle_two;
  PKCS11Context context(&manager);
  CK_FLAGS flags_one = CKF_SERIAL_SESSION;
  CK_FLAGS flags_two = CKF_SERIAL_SESSION | 1;
  int slotID = 1;
  ASSERT_EQ(CKR_OK, context.C_OpenSession(slotID, flags_one, NULL_PTR, NULL_PTR, &sessionHandle_one));
  //TODO: change session state to verify that session info is copied into new session
  ASSERT_EQ(CKR_OK, context.C_OpenSession(slotID, flags_two, NULL_PTR, NULL_PTR, &sessionHandle_two));
  ASSERT_NE(sessionHandle_one, sessionHandle_two);

  CK_SESSION_INFO pInfo;
  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_one, &pInfo));
  ASSERT_EQ(0, pInfo.ulDeviceError);
  ASSERT_EQ(flags_one, pInfo.flags);
  ASSERT_EQ(slotID, pInfo.slotID);

  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_two, &pInfo));
  ASSERT_EQ(0, pInfo.ulDeviceError);
  ASSERT_EQ(flags_two, pInfo.flags);
  ASSERT_EQ(slotID, pInfo.slotID);

  ASSERT_EQ(CKR_OK, context.C_CloseSession(sessionHandle_two));
  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_GetSessionInfo(sessionHandle_two, &pInfo));

  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_one, &pInfo));
  ASSERT_EQ(flags_one, pInfo.flags);

  ASSERT_EQ(CKR_OK, context.C_CloseSession(sessionHandle_one));
  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_GetSessionInfo(sessionHandle_one, &pInfo));

  delete cert;
}

TEST(PKCS11Context, C_CloseAllSessions) {
  MockCardManager manager;

  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getAuthCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));

  CK_SESSION_HANDLE sessionHandle_one;
  CK_SESSION_HANDLE sessionHandle_two;
  CK_SESSION_HANDLE sessionHandle_three;
  PKCS11Context context(&manager);
  CK_FLAGS flags = CKF_SERIAL_SESSION;
  int slotID_one = 0;
  int slotID_two = 1;

  ASSERT_EQ(CKR_OK, context.C_OpenSession(slotID_one, flags, NULL_PTR, NULL_PTR, &sessionHandle_one));
  ASSERT_EQ(CKR_OK, context.C_OpenSession(slotID_one, flags, NULL_PTR, NULL_PTR, &sessionHandle_two));
  ASSERT_EQ(CKR_OK, context.C_OpenSession(slotID_two, flags, NULL_PTR, NULL_PTR, &sessionHandle_three));

  CK_SESSION_INFO pInfo;
  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_one, &pInfo));
  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_two, &pInfo));
  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_three, &pInfo));

  ASSERT_EQ(CKR_OK, context.C_CloseAllSessions(slotID_one));
  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_GetSessionInfo(sessionHandle_one, &pInfo));
  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_GetSessionInfo(sessionHandle_two, &pInfo));
  ASSERT_EQ(CKR_OK, context.C_GetSessionInfo(sessionHandle_three, &pInfo));

  ASSERT_EQ(CKR_OK, context.C_CloseAllSessions(slotID_two));
  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_GetSessionInfo(sessionHandle_three, &pInfo));

  delete cert;
}