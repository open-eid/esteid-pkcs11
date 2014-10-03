/*!
	\file		pkcs11module.h
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2009-07-07 08:35:50 +0300 (Tue, 07 Jul 2009) $
*/
// Revision $Revision: 346 $

#include <smartcardpp/DynamicLibrary.h>

class pkcs11module : protected DynamicLibrary {
protected:
    typedef unsigned long  ULONG;
    typedef unsigned char  BYTE;
#pragma pack(push)
#pragma pack(2)
    typedef struct CK_VERSION {
        BYTE       major,minor;
    } CK_VERSION;

    typedef struct CK_INFO {
        CK_VERSION    cryptokiVersion;
        BYTE   manufacturerID[32];
        ULONG flags;
        BYTE   libraryDescription[32];
        CK_VERSION    libraryVersion;
        BYTE reserve[64]; //in case we have newer versions
    } CK_INFO;
    typedef struct CK_TOKEN_INFO {
        BYTE   label[32];
        BYTE   manufacturerID[32];
        BYTE   model[16];
        BYTE   serialNumber[16];
        ULONG  flags;
        ULONG  ulMaxSessionCount,ulSessionCount;
        ULONG  ulMaxRwSessionCount,ulRwSessionCount;
        ULONG  ulMaxPinLen,ulMinPinLen;
        ULONG  ulTotalPublicMemory,ulFreePublicMemory;
        ULONG  ulTotalPrivateMemory,ulFreePrivateMemory;
        CK_VERSION hardwareVersion,firmwareVersion;
        BYTE   utcTime[16];
        BYTE reserve[64];
    } CK_TOKEN_INFO;
#pragma pack(pop)
protected:
	ULONG (*pGetFunctionList)(void * pInitArgs);
	ULONG (*pInitialize)(void * pInitArgs);
	ULONG (*pFinalize)(void * pReserved);
	ULONG (*pGetInfo)(CK_INFO * pInfo);
	ULONG (*pGetSlotList)(BYTE tokenPresent,ULONG *pSlotList,ULONG * pulCount);
	ULONG (*pGetTokenInfo)(ULONG slotID,CK_TOKEN_INFO * pInfo);
	std::string buf2str(const void *in,size_t len);
public:
	pkcs11module(const char *n);
	~pkcs11module();
	void test(std::ostream &strm);
	};
