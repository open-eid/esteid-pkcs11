#include "gmock/gmock.h"
#include "OnePinPKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;

TEST(OnePinPKCS11Context, C_GetSlotList_ReturnTotalSlotCount) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(false));

  OnePinPKCS11Context context(&manager);

  CK_ULONG pulCount;

  ASSERT_EQ(CKR_OK, context.C_GetSlotList(CK_FALSE, NULL_PTR, &pulCount));
  ASSERT_EQ(2, pulCount);
}

TEST(OnePinPKCS11Context, C_GetSlotList_ReturnSlotCountForPresentTokens) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(0)).WillOnce(Return(false));
  EXPECT_CALL(manager, isInReader(1)).WillOnce(Return(true));

  OnePinPKCS11Context context(&manager);

  CK_ULONG pulCount;

  ASSERT_EQ(CKR_OK, context.C_GetSlotList(CK_TRUE, NULL_PTR, &pulCount));
  ASSERT_EQ(1, pulCount);
}

TEST(OnePinPKCS11Context, C_GetSlotList_BufferTooSmall) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(false));

  OnePinPKCS11Context context(&manager);

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(unsigned long));
  CK_ULONG pulCount = 1;

  ASSERT_EQ(CKR_BUFFER_TOO_SMALL, context.C_GetSlotList(CK_FALSE, pSlotList, &pulCount));
  ASSERT_EQ(2, pulCount);
}

TEST(OnePinPKCS11Context, C_GetSlotList_ForAllTokens) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(false));

  OnePinPKCS11Context context(&manager);

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(2 * sizeof(unsigned long));
  CK_ULONG pulCount = 2;

  ASSERT_EQ(CKR_OK, context.C_GetSlotList(CK_FALSE, pSlotList, &pulCount));
  ASSERT_EQ(2, pulCount);
  ASSERT_EQ(0, *pSlotList);
  ASSERT_EQ(2, *(pSlotList+1));
  ASSERT_NE(4, *(pSlotList+2));
}

TEST(OnePinPKCS11Context, C_GetSlotList_ForPresentTokens) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(0)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager, isInReader(1)).WillRepeatedly(Return(true));

  OnePinPKCS11Context context(&manager);

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(2 * sizeof(unsigned long));
  CK_ULONG pulCount = 2;

  ASSERT_EQ(CKR_OK, context.C_GetSlotList(CK_TRUE, pSlotList, &pulCount));
  ASSERT_EQ(2, *pSlotList);
  ASSERT_NE(4, *(pSlotList+1));
  ASSERT_EQ(1, pulCount);
}

TEST(OnePinPKCS11Context, C_GetSlotList_ThrowsException) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Throw(std::runtime_error("")));

  OnePinPKCS11Context context(&manager);

  CK_ULONG pulCount = 4;

  ASSERT_EQ(CKR_OK, context.C_GetSlotList(CK_TRUE, NULL_PTR, &pulCount));
  ASSERT_EQ(0, pulCount);
}
