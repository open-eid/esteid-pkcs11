/*!
	\file		pkcs11module.cpp
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2009-04-13 11:34:43 +0300 (Mon, 13 Apr 2009) $
*/
// Revision $Revision: 240 $

#include "precompiled.h"
#include "pkcs11module.h"

pkcs11module::pkcs11module(const char *n) : DynamicLibrary(n) {
	pGetFunctionList = (ULONG (*)(void * pInitArgs)) getProc("C_GetFunctionList");
	pInitialize = (ULONG (*)(void * pInitArgs))getProc("C_Initialize");
	pFinalize = (ULONG (*)(void * pReserved))getProc("C_Finalize");
	pGetInfo = (ULONG (*)(CK_INFO * pInfo))getProc("C_GetInfo");
	pGetSlotList = (ULONG (*)(BYTE tokenPresent,ULONG *pSlotList,ULONG * pulCount)) getProc("C_GetSlotList");
	pGetTokenInfo = (ULONG (*)(ULONG slotID,CK_TOKEN_INFO * pInfo)) getProc("C_GetTokenInfo");
	pInitialize(NULL);
	}
pkcs11module::~pkcs11module() {
	pFinalize(NULL);
	}

using std::endl;
using std::vector;

#define LENOF(x) (sizeof(x) / sizeof(*x))
#define GETSTR(x) buf2str((const char*)x,sizeof(x))

std::string pkcs11module::buf2str(const void *in,size_t len) {
	std::string tmp((char *)in,len);
	if(!*tmp.begin()) tmp.clear();
	tmp.erase(tmp.find_last_not_of(" \t")+1);
	return tmp;
	}

void pkcs11module::test(std::ostream &strm) {
	ULONG ret;
	CK_INFO inf;
	if(0 != (ret = pGetInfo(&inf))) {
		strm << "GetInfo failed (code: "<< ret << ")" << endl;
		return;
		}
	strm << "version:" << (int ) inf.cryptokiVersion.major << "." << (int ) inf.cryptokiVersion.minor << endl;
	strm << "libver:" << (int) inf.libraryVersion.major << "." << (int) inf.libraryVersion.minor << endl;
	strm << "manufacturer: " << GETSTR(inf.manufacturerID) << 
			" description:" << GETSTR(inf.libraryDescription) << endl;
	ULONG slotCount = 100;
	vector<ULONG> arrSlots(100,0);
	if (0 != (ret = pGetSlotList(0,&arrSlots[0],&slotCount))) {
		strm << "GetSlotList failed (code: " 	<< ret <<")" << endl;
		return;
		};
	arrSlots.resize(slotCount);
	strm << "slotcount:" << arrSlots.size() << endl;
	for(vector<ULONG>::iterator it = arrSlots.begin(); it != arrSlots.end();it++) {
		CK_TOKEN_INFO tInfo;
		strm << "slot ID [" << *it << "]" << endl;
		if (0!= (ret = pGetTokenInfo(*it,&tInfo))) {
			if (ret == 0xE0 || ret == 0x32) //not present
				strm << "\t[EMPTY]" << endl;
			else 
				strm << "\tGetTokenInfo failed (code: "<< ret << ")" << endl;
			}
		else {
			if (GETSTR(tInfo.label).length() == 0) continue;
			strm << "\tLabel:'" << GETSTR(tInfo.label) << "'" 
				<< "\tSerial:'" << GETSTR(tInfo.serialNumber) << "'" << endl;
			strm << "\tManufacturer:'" << GETSTR(tInfo.manufacturerID) << "'" 
				<< "\tModel:'" << GETSTR(tInfo.model) << "'" 
				<< endl;
			strm << "\tflags: " << tInfo.flags << endl;
			}
		}
}

