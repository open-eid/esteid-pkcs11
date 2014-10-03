#include "gmock/gmock.h"
#include "PKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;

TEST(PKCS11Context, C_GetSlotList_ReturnTotalSlotCount) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(false));

  PKCS11Context context(&manager);

  CK_ULONG pulCount;

  ASSERT_EQ(CKR_OK, context.C_GetSlotList(CK_FALSE, NULL_PTR, &pulCount));
  ASSERT_EQ(4, pulCount);
}

TEST(PKCS11Context, C_GetSlotList_ReturnSlotCountForPresentTokens) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(0)).WillOnce(Return(false));
  EXPECT_CALL(manager, isInReader(1)).WillOnce(Return(true));

  PKCS11Context context(&manager);

  CK_ULONG pulCount;

  ASSERT_EQ(CKR_OK, context.C_GetSlotList(CK_TRUE, NULL_PTR, &pulCount));
  ASSERT_EQ(2, pulCount);
}

TEST(PKCS11Context, C_GetSlotList_BufferTooSmall) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(false));

  PKCS11Context context(&manager);

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(2 * sizeof(unsigned long));
  CK_ULONG pulCount = 2;

  ASSERT_EQ(CKR_BUFFER_TOO_SMALL, context.C_GetSlotList(CK_FALSE, pSlotList, &pulCount));
  ASSERT_EQ(0, *pSlotList);
  ASSERT_EQ(1, *(pSlotList+1));
  ASSERT_NE(2, *(pSlotList+2));
  ASSERT_EQ(4, pulCount);
}

TEST(PKCS11Context, C_GetSlotList_ForAllTokens) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(_)).WillRepeatedly(Return(false));

  PKCS11Context context(&manager);

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(4 * sizeof(unsigned long));
  CK_ULONG pulCount = 4;

  ASSERT_EQ(CKR_OK, context.C_GetSlotList(CK_FALSE, pSlotList, &pulCount));
  ASSERT_EQ(0, *pSlotList);
  ASSERT_EQ(1, *(pSlotList+1));
  ASSERT_EQ(2, *(pSlotList+2));
  ASSERT_EQ(3, *(pSlotList+3));
  ASSERT_NE(4, *(pSlotList+4));
  ASSERT_EQ(4, pulCount);
}

TEST(PKCS11Context, C_GetSlotList_ForPresentTokens) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(2));
  EXPECT_CALL(manager, isInReader(0)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager, isInReader(1)).WillRepeatedly(Return(true));

  PKCS11Context context(&manager);

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(4 * sizeof(unsigned long));
  CK_ULONG pulCount = 4;

  ASSERT_EQ(CKR_OK, context.C_GetSlotList(CK_TRUE, pSlotList, &pulCount));
  ASSERT_EQ(2, *pSlotList);
  ASSERT_EQ(3, *(pSlotList+1));
  ASSERT_NE(4, *(pSlotList+2));
  ASSERT_EQ(2, pulCount);
}

TEST(PKCS11Context, C_GetSlotList_ThrowsException) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Throw(std::runtime_error("")));

  PKCS11Context context(&manager);

  CK_ULONG pulCount = 4;

  ASSERT_EQ(CKR_OK, context.C_GetSlotList(CK_TRUE, NULL_PTR, &pulCount));
  ASSERT_EQ(0, pulCount);
}