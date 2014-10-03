#include "gmock/gmock.h"
#include "PKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;
using namespace std;

TEST(PKCS11Context, C_GetSlotInfo_InvalidSlot) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));

  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_SLOT_ID_INVALID, context.C_GetSlotInfo(4, NULL_PTR));
}

TEST(PKCS11Context, C_GetSlotInfo_CardInReader) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(0)).WillOnce(Return(true));
//  EXPECT_CALL(manager, getReaderName()).WillOnce(Return("OMNIKEY 1021"));

  PKCS11Context context(&manager);
  CK_SLOT_INFO_PTR pInfo = (CK_SLOT_INFO_PTR) malloc(sizeof(CK_SLOT_INFO));
  ASSERT_EQ(CKR_OK, context.C_GetSlotInfo(1, pInfo));

  char result[65];
  ASSERT_STREQ("OMNIKEY 1021                                                    ", nullTerminatedString(result, pInfo->slotDescription, 64));
  ASSERT_STREQ("EstEID                          ", nullTerminatedString(result, pInfo->manufacturerID, 32));

  ASSERT_EQ(1, pInfo->hardwareVersion.major);
  ASSERT_EQ(0, pInfo->hardwareVersion.minor);
  ASSERT_EQ(1, pInfo->firmwareVersion.major);
  ASSERT_EQ(0, pInfo->firmwareVersion.minor);

  CK_FLAGS flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT | CKF_TOKEN_PRESENT;
  ASSERT_EQ(flags, pInfo->flags);
}

TEST(PKCS11Context, C_GetSlotInfo_CardNotInReader) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(0)).WillOnce(Return(false));

  PKCS11Context context(&manager);
  CK_SLOT_INFO_PTR pInfo = (CK_SLOT_INFO_PTR) malloc(sizeof(CK_SLOT_INFO));
  ASSERT_EQ(CKR_OK, context.C_GetSlotInfo(1, pInfo));

  CK_FLAGS flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
  ASSERT_EQ(flags, pInfo->flags);
}

TEST(PKCS11Context, C_GetSlotInfo_ThrowsException) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Throw(std::runtime_error("")));

  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_GENERAL_ERROR, context.C_GetSlotInfo(1, NULL_PTR));
}
