/*
 * ESTEID PKCS11 module
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL)
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 *
 */

#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>
#pragma once
using std::vector;
using std::string;
using std::runtime_error;

typedef unsigned char byte;

typedef vector<byte> byteVec;
typedef byteVec::iterator byteIter;

typedef size_t asnsize;

class asn_error:public runtime_error {
public:
	asn_error(const char *w):runtime_error(w){};
	asn_error(const char *w,byte expected,byte seen):runtime_error("asn expected byte") {}
	asn_error(const char *w,asnsize decoded,asnsize input):runtime_error("asn size mismatch") {}
};

class asnObject: public byteVec
{
	const asnObject &operator=(const asnObject &);
public:
	enum primitiveTag {
		BOOLEAN			 = 0x01,
		INTEGER          = 0x02,
		BITSTRING        = 0x03,
		OCTETSTRING      = 0x04,
		NULLDATA         = 0x05,
		OBJECTIDENTIFIER = 0x06,
		OBJDESCRIPTOR    = 0x07,
		EXTERNAL         = 0x08,
		REAL             = 0x09,
		ENUMERATED       = 0x0A,
		EMBEDDEDPDV      = 0x0B,
		UTF8String       = 0x0C,
		SEQUENCE         = 0x10,
		SET              = 0x11,
		NumericString    = 0x12,
		PrintableString  = 0x13,
		TeletexString    = 0x14,
		IA5String        = 0x16,
		UTCTime          = 0x17,
		GeneralizedTime  = 0x18,
		GRAPHICSTRING    = 0x19,
		VISIBLESTRING    = 0x1A,
		GENERALSTRING    = 0x1B,
		UNIVERSALSTRING  = 0x1C,
		BMPSTRING        = 0x1E
		};
private:
	int tab;
	void decode(int tab);
	void init();
protected:
public:
	bool expl_tag;
	byte tag;
	vector<asnObject*> contents;
	asnObject* findExplicit(byte n);
	asnObject* findSeq(byte n);
	asnObject(byteVec &in,std::ostream &pout);
	asnObject(byteIter from,byteIter to,int tabs,std::ostream &pout);
public:
	std::ostream &bout;
	asnsize size;
	byteIter start;
	byteIter stop;
	byteIter body_start;
	~asnObject(void);
};

