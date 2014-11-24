#include "gmock/gmock.h"
#include "PKCS11Context.h"
#include "esteid-unit-test.h"

TEST(PKCS11Context, C_GetInfo) {
  PKCS11Context context;

  CK_INFO_PTR pInfo = (CK_INFO_PTR)malloc(sizeof(CK_INFO));

  ASSERT_EQ(CKR_OK, context.C_GetInfo(pInfo));
  ASSERT_EQ(2, pInfo->cryptokiVersion.major);
  ASSERT_EQ(20, pInfo->cryptokiVersion.minor);
  ASSERT_EQ(0, pInfo->flags);
  ASSERT_EQ(MAJOR_VER, pInfo->libraryVersion.major);
  ASSERT_EQ(MINOR_VER, pInfo->libraryVersion.minor);

  //according to PKCS11 spec manufacturerID and libraryDescription should be "not" null-terminated
  char result[33];
  ASSERT_STREQ("EstEID (pkcs11 opensource)      ", nullTerminatedString(result, pInfo->manufacturerID, 32));
  ASSERT_STREQ("EstEID PKCS#11 Library          ", nullTerminatedString(result, pInfo->libraryDescription, 32));

  free(pInfo);
}