#include "gmock/gmock.h"
#include "PKCS11Context.h"

TEST(PKCS11Context, C_GetMechanismInfo) {
  CardManager manager;

  PKCS11Context context(&manager);
  CK_MECHANISM_INFO pInfo;
  ASSERT_EQ(CKR_OK, context.C_GetMechanismInfo(0, 0, &pInfo));
  ASSERT_EQ(1024, pInfo.ulMinKeySize);
  ASSERT_EQ(2048, pInfo.ulMaxKeySize);
  CK_FLAGS flags = CKF_HW | CKF_ENCRYPT | CKF_SIGN | CKF_DECRYPT;
  ASSERT_EQ(flags, pInfo.flags);
}
