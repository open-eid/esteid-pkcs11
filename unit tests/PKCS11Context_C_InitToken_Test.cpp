#include "gmock/gmock.h"
#include "PKCS11Context.h"

TEST(PKCS11Context, C_InitToken) {
  CardManager manager;
  PKCS11Context context(&manager);
  ASSERT_EQ(CKR_OK, context.C_InitToken(0, 0, 0, 0));
}
