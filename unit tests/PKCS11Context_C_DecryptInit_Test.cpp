#include "gmock/gmock.h"
#include "PKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;
using namespace std;

TEST(PKCS11Context, C_DecryptInit_InvalidSession) {
  MockCardManager manager;
  PKCS11Context context(&manager);

  ASSERT_EQ(CKR_SESSION_HANDLE_INVALID, context.C_DecryptInit(101, NULL, NULL_PTR));
}

TEST(PKCS11Context, C_DecryptInit_UserNotLoggedIn) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));

  ASSERT_EQ(CKR_USER_NOT_LOGGED_IN, context.C_DecryptInit(session, NULL, NULL_PTR));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));

  delete cert;
}

TEST(PKCS11Context, C_DecryptInit_InvalidMechanism) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)"0000", 4));

  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_RSA_9796;
  ASSERT_EQ(CKR_MECHANISM_INVALID, context.C_DecryptInit(session, &mechanism, NULL_PTR));
  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));
}

TEST(PKCS11Context, C_DecryptInit) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  ByteVec *cert = getCert();
  EXPECT_CALL(manager, getSignCert()).WillRepeatedly(Return(*cert));
  EXPECT_CALL(manager, validateSignPin(_,_));

  CK_SESSION_HANDLE session;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_OpenSession(1, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
  ASSERT_EQ(CKR_OK, context.C_Login(session, 0, (unsigned char*)"0000", 4));

  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_RSA_PKCS;
  ASSERT_EQ(CKR_OK, context.C_DecryptInit(session, &mechanism, NULL_PTR));


  ASSERT_EQ(CKR_OK, context.C_Logout(session));
  ASSERT_EQ(CKR_OK, context.C_CloseSession(session));
}
