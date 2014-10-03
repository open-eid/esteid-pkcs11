#include "OnePinPKCS11Context.h"

OnePinPKCS11Context::OnePinPKCS11Context(CardManager *manager) : PKCS11Context(manager) {
}

OnePinPKCS11Context::OnePinPKCS11Context() : PKCS11Context() {
}

bool OnePinPKCS11Context::checkSlot(CK_SLOT_ID slotID) {
  return IS_SIGN_SLOT || PKCS11Context::checkSlot(slotID);
}

CK_RV OnePinPKCS11Context::C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  *pulCount *= 2;
  CK_SLOT_ID_PTR tmpList = (pSlotList == NULL_PTR) ? NULL_PTR : (CK_SLOT_ID_PTR) malloc(*pulCount * sizeof(unsigned long));
  CK_RV result = PKCS11Context::C_GetSlotList(tokenPresent, tmpList, pulCount);
  if (pSlotList != NULL_PTR) {
    for (int i = 0; i < *pulCount / 2; i++) {
      *(pSlotList + i) = tmpList[i * 2];
    }
    free(tmpList);
  }
  *pulCount /= 2;
  return result;
}
