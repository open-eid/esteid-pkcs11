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

#include "asnObject.h"

class asnCertificate : public asnObject {
	const asnCertificate &operator=(const asnCertificate &);
	asnObject * signatureValue;
	asnObject * signatureAlgorithm;

	asnObject * version;
	asnObject * serialNumber;
	asnObject * signatureAlg;
	asnObject * issuerName;
	asnObject * validityPeriod;
	asnObject * subjectName;
	asnObject * publicKeyInfo;
	asnObject * extensions;
  vector<byte> trimBeginning(vector<byte> result);
  void init();

public:
  asnCertificate(byteVec &in,std::ostream &pout);
  asnObject *findExtension(std::string ext);
  string getSubjectAltName();
  bool isTimeValid(int numDaysFromNow = 0);
  string getValidFrom();
  string getValidTo();
  string getSubject();
  vector<byte> getSubjectCN();
  vector<byte> getSubjectO();
  vector<byte> getSubjectOU();
  vector<byte> getIssuerCN();
  vector<byte> getIssuerO();
  vector<byte> getIssuerOU();
  vector<byte> getIssuerBlob();
  vector<byte> getSerialBlob();
  vector<byte> getSubjectBlob();
  vector<byte> getPubKey();
  bool checkKeyUsage(std::string keyUsageId);
  bool hasExtKeyUsage();

  vector<byte> getModulus();
  vector<byte> getPublicExponent();

};
