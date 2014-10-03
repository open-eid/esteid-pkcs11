#include "gmock/gmock.h"
#include "OnePinPKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;
using namespace std;

TEST(OnePinPKCS11Context, C_GetSlotInfo_SigningSlotsAreNotValid) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(2));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(true));

  OnePinPKCS11Context context(&manager);
  CK_SLOT_INFO pInfo;
  ASSERT_EQ(CKR_OK, context.C_GetSlotInfo(0, &pInfo));
  ASSERT_EQ(CKR_SLOT_ID_INVALID, context.C_GetSlotInfo(1, &pInfo));
  ASSERT_EQ(CKR_OK, context.C_GetSlotInfo(2, &pInfo));
  ASSERT_EQ(CKR_SLOT_ID_INVALID, context.C_GetSlotInfo(3, &pInfo));
}