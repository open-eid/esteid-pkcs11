#include "gmock/gmock.h"
#include "PKCS11Context.h"
#include "esteid-unit-test.h"

using namespace testing;

TEST(PKCS11Context, C_GetMechanismList_InvalidSlot) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));

  PKCS11Context context(&manager);
  CK_ULONG pulCount;
  ASSERT_EQ(CKR_SLOT_ID_INVALID, context.C_GetMechanismList(2, NULL_PTR, &pulCount));
}

TEST(PKCS11Context, C_GetMechanismList_GetMechanismCount) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));

  PKCS11Context context(&manager);
  CK_ULONG pulCount;
  ASSERT_EQ(CKR_OK, context.C_GetMechanismList(0, NULL_PTR, &pulCount));
  ASSERT_EQ(1, pulCount);
}

TEST(PKCS11Context, C_GetMechanismList_BufferTooSmall) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillOnce(Return(1));

  PKCS11Context context(&manager);
  CK_ULONG pulCount = 0;
  CK_MECHANISM_TYPE pMechanismList[10];
  ASSERT_EQ(CKR_BUFFER_TOO_SMALL, context.C_GetMechanismList(0, pMechanismList, &pulCount));
}

TEST(PKCS11Context, C_GetMechanismList_ListSupportedMechanisms) {
  MockCardManager manager;
  EXPECT_CALL(manager, getTokenCount(true)).WillRepeatedly(Return(1));

  PKCS11Context context(&manager);
  CK_ULONG pulCount;
  ASSERT_EQ(CKR_OK, context.C_GetMechanismList(0, NULL_PTR, &pulCount));

  CK_MECHANISM_TYPE_PTR pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(pulCount * sizeof(CK_MECHANISM_TYPE));
  ASSERT_EQ(CKR_OK, context.C_GetMechanismList(0, pMechanismList, &pulCount));
  ASSERT_EQ(1, pulCount);
  ASSERT_EQ(CKM_RSA_PKCS, pMechanismList[0]);
}