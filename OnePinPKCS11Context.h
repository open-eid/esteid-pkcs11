#include "PKCS11Context.h"

class OnePinPKCS11Context : public PKCS11Context {

protected:
  bool checkSlot(CK_SLOT_ID slotID);

public:
  OnePinPKCS11Context();
  OnePinPKCS11Context(CardManager *);
  CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
};
