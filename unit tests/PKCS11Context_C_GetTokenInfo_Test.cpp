#include "gmock/gmock.h"
#include "PKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;
using namespace std;

TEST(PKCS11Context, C_GetTokenInfo_CardNotInReader) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(false));

  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_DEVICE_REMOVED, context.C_GetTokenInfo(1, NULL_PTR));
}

TEST(PKCS11Context, C_GetTokenInfo_WrongSlotID) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));

  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_SLOT_ID_INVALID, context.C_GetTokenInfo(2, NULL_PTR));
}

TEST(PKCS11Context, C_GetTokenInfo_WithException) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Throw(std::runtime_error("")));

  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_GENERAL_ERROR, context.C_GetTokenInfo(2, NULL_PTR));
}

TEST(PKCS11Context, C_GetTokenInfo_CommonPart) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(true));
  EXPECT_CALL(manager, isSecureConnection()).WillOnce(Return(false));
  EXPECT_CALL(manager, readCardName(_)).WillRepeatedly(Return("Igor Žaikovski"));
  EXPECT_CALL(manager, getRetryCounts(_, _, _)).WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(3),Return(true)));

  PKCS11Context context(&manager);
  CK_TOKEN_INFO pInfo;
  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(0, &pInfo));
  char result[33];
  ASSERT_STREQ("Igor Žaikovski (PIN1, Auth)    ", nullTerminatedString(result, pInfo.label, 32));
  ASSERT_STREQ("EstEid smartcardpp              ", nullTerminatedString(result, pInfo.manufacturerID, 32));
  ASSERT_STREQ("original        ", nullTerminatedString(result, pInfo.model, 16));
  ASSERT_STREQ("X0010119        ", nullTerminatedString(result, pInfo.serialNumber, 16));

  ASSERT_EQ(10, pInfo.ulMaxSessionCount);
  ASSERT_EQ(0, pInfo.ulSessionCount);
  ASSERT_EQ(10, pInfo.ulMaxRwSessionCount);
  ASSERT_EQ(0, pInfo.ulRwSessionCount);
  ASSERT_EQ(12, pInfo.ulMaxPinLen);
  ASSERT_EQ(4, pInfo.ulMinPinLen);
  ASSERT_EQ(2048, pInfo.ulTotalPublicMemory);
  ASSERT_EQ(0, pInfo.ulFreePublicMemory);
  ASSERT_EQ(2048, pInfo.ulTotalPrivateMemory);
  ASSERT_EQ(0, pInfo.ulFreePrivateMemory);
  ASSERT_EQ(1, pInfo.hardwareVersion.major);
  ASSERT_EQ(0, pInfo.hardwareVersion.minor);
  ASSERT_EQ(1, pInfo.firmwareVersion.major);
  ASSERT_EQ(0, pInfo.firmwareVersion.minor);
}

TEST(PKCS11Context, C_GetTokenInfo_PIN1_UTF8) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(true));
  EXPECT_CALL(manager, isSecureConnection()).WillOnce(Return(false));
  EXPECT_CALL(manager, readCardName(_)).WillRepeatedly(Return("Igor Žaikovski"));
  EXPECT_CALL(manager, getRetryCounts(_, _, _)).WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(3),Return(true)));

  PKCS11Context context(&manager);
  CK_TOKEN_INFO pInfo;
  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(0, &pInfo));
  char result[33];
  ASSERT_STREQ("Igor Žaikovski (PIN1, Auth)    ", nullTerminatedString(result, pInfo.label, 32));
}

TEST(PKCS11Context, C_GetTokenInfo_PIN2_UTF8) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillOnce(Return(true));
  EXPECT_CALL(manager, isSecureConnection()).WillOnce(Return(false));
  EXPECT_CALL(manager, readCardName(_)).WillRepeatedly(Return("Igor Žaikovski"));
  EXPECT_CALL(manager, getRetryCounts(_, _, _)).WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(3),Return(true)));

  PKCS11Context context(&manager);
  CK_TOKEN_INFO pInfo;
  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(1, &pInfo));
  char result[33];
  ASSERT_STREQ("Igor Žaikovski (PIN2, Sign)    ", nullTerminatedString(result, pInfo.label, 32));
}

TEST(PKCS11Context, C_GetTokenInfo_Flags) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(manager, isDigiID()).WillRepeatedly(Return(true));
  EXPECT_CALL(manager, readCardName(_)).WillRepeatedly(Return("Igor Žaikovski"));
  EXPECT_CALL(manager, isSecureConnection())
      .WillOnce(Return(false))
      .WillOnce(Return(true))
      .WillOnce(Return(true))
      .WillOnce(Return(true))
      .WillOnce(Return(true))
      .WillOnce(Return(false))
      .WillOnce(Return(false))
      .WillOnce(Return(false));
  EXPECT_CALL(manager, getRetryCounts(_, _, _))
      .WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(3),Return(true)))
      .WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(3),Return(true)))
      .WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(2),Return(true)))
      .WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(1),Return(true)))
      .WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(0),Return(true)))
      .WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(2),Return(true)))
      .WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(1),Return(true)))
      .WillOnce(DoAll(SetArgReferee<0>(3), SetArgReferee<1>(3), SetArgReferee<2>(0),Return(true)));

  PKCS11Context context(&manager);
  CK_TOKEN_INFO pInfo;
  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(1, &pInfo));
  CK_FLAGS flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
  ASSERT_EQ(flags, pInfo.flags);

  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(1, &pInfo));
  flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH;
  ASSERT_EQ(flags, pInfo.flags);

  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(1, &pInfo));
  flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_USER_PIN_COUNT_LOW;
  ASSERT_EQ(flags, pInfo.flags);

  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(1, &pInfo));
  flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY;
  ASSERT_EQ(flags, pInfo.flags);

  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(1, &pInfo));
  flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_LOCKED;
  ASSERT_EQ(flags, pInfo.flags);

  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(1, &pInfo));
  flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_COUNT_LOW;
  ASSERT_EQ(flags, pInfo.flags);

  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(1, &pInfo));
  flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY;
  ASSERT_EQ(flags, pInfo.flags);

  ASSERT_EQ(CKR_OK, context.C_GetTokenInfo(1, &pInfo));
  flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_LOCKED;
  ASSERT_EQ(flags, pInfo.flags);
}
