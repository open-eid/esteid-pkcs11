/*
 * ESTEID PKCS11 module
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL) or the BSD License (see LICENSE.BSD).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 *
 */

#include "precompiled.h"
#include "asnCertificate.h"
#include <sstream>
#include <time.h>

#define idSubjectAltName "2.5.29.17"
#define idKeyUsage "2.5.29.15"
#define idExtKeyUsage "2.5.29.37"
#define idCrlPoints "2.5.29.31"

asnCertificate::asnCertificate(byteVec &in,std::ostream &pout):
		asnObject(in,pout),extensions(0) {
			init();
		}

void asnCertificate::init() {
	if (contents.size() != 3)
		throw asn_error("Certificate must consist of three elements");
	asnObject * tbsCertificate = contents[0];
	signatureAlgorithm  = contents[1];
	signatureValue = contents[2];
	if (tbsCertificate->contents.size() < 7)
		throw asn_error("tbsCertificate must have at least 7 elements");

	version = tbsCertificate->contents[0];
	serialNumber = tbsCertificate->contents[1];
	signatureAlg = tbsCertificate->contents[2];
	issuerName = tbsCertificate->contents[3];
	validityPeriod = tbsCertificate->contents[4];
	if (validityPeriod->contents.size() != 2)
		throw asn_error("validityPeriod should have 2 members");
	subjectName = tbsCertificate->contents[5];
	publicKeyInfo = tbsCertificate->contents[6];

	if (tbsCertificate->contents.size() >= 8)
		extensions = tbsCertificate->contents[7];
	}

std::string getAlgid(asnObject *obj) {
  if (obj->tag != asnObject::OBJECTIDENTIFIER)
    throw asn_error("expected objectidentifier");
  if (obj->size < 3) throw asn_error("invalid OBJID");
  byteVec body = byteVec(obj->body_start, obj->stop);
  unsigned char m1 = (body[0] & 0x28) ? 0x28 :
      (body[0] & 0x50 ? 0x50 : 0);
  if (!m1) throw asn_error("invalid OBJID byte0");
  unsigned char val1 = (m1 >> 5);
  unsigned char val2 = body[0] & (~m1);
  std::ostringstream buf;
  buf << (int) val1 << "." << (int) val2;
  for (size_t i = 1; i < body.size(); i++) {
    int val = body[i];
    while (body[i] & 0x80 && i < body.size())
      val = ((val & 0x7F) << 7) & (body[i++] & 0x7F);
    buf << "." << (int) val;
  }
  string objStr = buf.str();
  return objStr;
}

asnObject *asnCertificate::findExtension(std::string ext) {
	if (!extensions)
		return 0;
	if (!extensions->expl_tag
		|| extensions->tag != 3
		|| extensions->contents.size() != 1 )
		throw "invalid extlist";

	asnObject *extList = extensions->contents[0];
	for (size_t i= 0;i < extList->contents.size();i++) {
		asnObject *pExt = extList->contents[i];
		if (pExt->tag != SEQUENCE || (pExt->contents.size() != 2 && pExt->contents.size() != 3))
			throw asn_error("invalid extension");
		asnObject *p0 = pExt->contents[0];
		string extId = getAlgid(p0);
		asnObject *value = pExt->contents[1];
		if (pExt->contents.size() == 3 )
			value = pExt->contents[2];
		if (extId == ext)
			return value;
		}
	return 0;
	}

string asnCertificate::getSubjectAltName() {
	asnObject * ext = findExtension(idSubjectAltName);
	if (!ext)
        return "";
	asnObject decode(ext->body_start,ext->stop,0,bout);
	if (decode.tag!=SEQUENCE)
		throw asn_error("invalid altName");
	std::string ret;
	for(size_t i=0; i < decode.contents.size(); i++) {
		ret.resize(ret.size()+ decode.contents[i]->size);
		copy(decode.contents[i]->body_start,decode.contents[i]->stop,
			ret.begin());
		}
	return ret;
	}

bool asnCertificate::hasExtKeyUsage() {
	return (0!=findExtension(idExtKeyUsage));
	}

bool asnCertificate::checkKeyUsage(string id) {
	asnObject * ext = findExtension(idExtKeyUsage);
	if (!ext) return false;
	asnObject decode(ext->body_start,ext->stop,0,bout);
	if (decode.tag!=SEQUENCE)
		throw asn_error("invalid ExtKeyUsage");
	for(size_t i=0; i < decode.contents.size(); i++) {
		string comp = getAlgid(decode.contents[i]);
		if (comp == id ) return true;
		}
	return false;
	}

const char *arrNameIds[][2] = {
	{"2.5.4.3","CN"},
	{"2.5.4.4","SN"},
	{"2.5.4.5","Serial Number"},
	{"2.5.4.6","C"},
	{"2.5.4.10","O"},
	{"2.5.4.11","OU"},
	{"2.5.4.42","G"},
	};

vector<byte> getNameValue(asnObject *p, string extId) {
  vector<byte> retVal;
  for (size_t i = 0; i < p->contents.size(); i++) {
    asnObject *n = p->contents[i];
    if (n->contents.size() != 1) throw asn_error("bad namevalue");
    asnObject *nv = n->contents[0];
    if (nv->contents.size() != 2) throw asn_error("bad namevalue, expecting 2 members");
    if (extId == getAlgid(nv->contents[0])) {
      retVal.resize(nv->contents[1]->size);
      copy(nv->contents[1]->body_start, nv->contents[1]->stop, retVal.begin());
    }
  }
  return retVal;
}

vector<byte> asnCertificate::getSubjectCN() {
	return getNameValue(subjectName,"2.5.4.3");
	}

vector<byte> asnCertificate::getSubjectO() {
	return getNameValue(subjectName,"2.5.4.10");
	}

vector<byte> asnCertificate::getSubjectOU() {
	return getNameValue(subjectName,"2.5.4.11");
	}

vector<byte> asnCertificate::getIssuerCN() {
	return getNameValue(issuerName,"2.5.4.3");
	}

vector<byte> asnCertificate::getIssuerO() {
	return getNameValue(issuerName,"2.5.4.10");
	}

vector<byte> asnCertificate::getIssuerOU() {
	return getNameValue(issuerName,"2.5.4.11");
	}

vector<byte> asnCertificate::getIssuerBlob() {
	return vector<byte>(issuerName->start,issuerName->stop);
	}

vector<byte> asnCertificate::getSerialBlob() {
	return vector<byte>(serialNumber->body_start,serialNumber->stop);
	}

vector<byte> asnCertificate::getSubjectBlob() {
	return vector<byte>(subjectName->start,subjectName->stop);
	}

vector<byte> asnCertificate::getPubKey() {
	vector<byte> retVal;
	asnObject *target = publicKeyInfo->contents[1];
	retVal.resize(target->size - 1);
	copy(target->body_start +1 ,target->stop,retVal.begin());
	return retVal;
}

vector<byte> asnCertificate::getModulus() {
  asnObject decodedPublicKey(publicKeyInfo->contents[1]->body_start + 1, publicKeyInfo->contents[1]->stop, 0, bout);
  return trimBeginning(vector<byte>(decodedPublicKey.contents[0]->body_start, decodedPublicKey.contents[0]->stop));
}

vector<byte> asnCertificate::getPublicExponent() {
  asnObject decodedPublicKey(publicKeyInfo->contents[1]->body_start + 1, publicKeyInfo->contents[1]->stop, 0, bout);
  return trimBeginning(vector<byte>(decodedPublicKey.contents[1]->body_start, decodedPublicKey.contents[1]->stop));
}

vector<byte> asnCertificate::trimBeginning(vector<byte> result) {
  while (result[0] == 0) {
    result.erase(result.begin());
  }
  return result;
}

string getDateStr(asnObject *v) {
	if (v->size != 13) throw asn_error("invalid date");

	string val(10,'.'),a2("20");
	copy(a2.begin(),a2.end(), val.begin() + 6 );
	copy(v->body_start + 0,v->body_start +2, val.begin() + 8 );
	copy(v->body_start + 2,v->body_start +4, val.begin() + 3);
	copy(v->body_start + 4,v->body_start +6, val.begin() + 0);
	return val;
	}

string asnCertificate::getValidFrom() {
	return getDateStr(validityPeriod->contents[0]);
	}

string asnCertificate::getValidTo() {
	return getDateStr(validityPeriod->contents[1]);
	}

bool asnCertificate::isTimeValid(int numDaysFromNow) {
	time_t ti;
	struct tm mTime;
	time(&ti);
#ifdef _WIN32
	localtime_s(&mTime,&ti);
#else
	localtime_r(&ti,&mTime);
#endif
	mTime.tm_mday +=numDaysFromNow;
	time_t ttmp = mktime(&mTime);
#ifdef _WIN32
	localtime_s(&mTime,&ttmp);
#else
	localtime_r(&ttmp,&mTime);
#endif
	std::ostringstream buf;
	buf << std::setfill('0') << std::setw(2) << (mTime.tm_year - 100);
	buf << std::setfill('0') << std::setw(2) << (mTime.tm_mon + 1) ;
	buf << std::setfill('0') << std::setw(2) << mTime.tm_mday;
	string local = buf.str(),cer(13,'0');
	copy(validityPeriod->contents[1]->body_start,
		validityPeriod->contents[1]->stop,cer.begin());
	return cer > local;
	}
