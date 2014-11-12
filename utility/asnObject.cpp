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

#include "precompiled.h"
#include "asnObject.h"

asnObject::asnObject(byteVec &in,std::ostream &pout):byteVec(in),tab(0),bout(pout) {init();}
asnObject::asnObject(byteIter from,byteIter to,int tabs,std::ostream &pout):tab(0),
		bout(pout),start(from),stop(to) {
		decode(tabs);
		}

asnObject::~asnObject(void) {
	while(!contents.empty()) {
		delete contents.back();
		contents.pop_back();
		};
	}

asnObject* asnObject::findExplicit(byte n) {
	for(vector<asnObject*>::iterator p = contents.begin();p != contents.end() ;p++)
		if ( (*p)->expl_tag && (*p)->tag == n 
			&& (*p)->contents.size() == 1 ) return (*p)->contents.front() ;
	return NULL ;
	}
asnObject* asnObject::findSeq(byte n) {
	for(vector<asnObject*>::iterator p = contents.begin();p != contents.end() ;p++)
		if ( !(*p)->expl_tag && (*p)->tag == SEQUENCE) return (*p) ;
	return NULL ;
	}

void asnObject::decode(int tab) {
	byteIter p = start + 2;

  if (stop - start < 2)
    throw asn_error("too few bytes as input");

  tag = *start;
	size = *(start + 1);
	body_start = start + 2 + ( size & 0x80 ? size & 0x7F : 0 ) ;

  if (body_start > stop )
    throw asn_error("content points too far out");

  if(size & 0x80) {
		if (body_start > start + 6 )
      throw asn_error("too many size bytes");

    size = 0;
		while(p < body_start)
      size= (size << 8) + *p++;
	}

	for (int i=tab ; i>0;i--)
    bout << " ";

  bout.setf(std::ios::hex, std::ios::basefield);
	bout << std::setw(2) <<  std::setfill('0') << (int) tag 
			<< " "
			<< std::setw(4) << (int) size;;

	if (body_start + size > stop)
    throw asn_error("size is beyond buffer end");

	stop = body_start + size;
	expl_tag = (tag & 0xA0) == 0xA0;

  if (tag & 0x20) { //constructed, bit6 = 1
		tag &= 0x1F;
		bout << std::endl;
		tab+=2;
		while(p < stop) {
			contents.push_back(new asnObject(p,stop,tab,bout));
			p = contents.back()->stop;
	  }
		tab-=2;
		if (p != stop)
      throw asn_error("garbage bytes");
		}
	else { //bit 6= 0 
		if ( (tag & 0x1F) == 0x1F) 
			throw asn_error("complex tagging");
		while(p < stop) bout << " " << std::setw(2) << std::setfill('0')
      << (int)*p++;
		bout << std::endl;
	}
}

void asnObject::init() {
	start = begin();
	stop = end();
	decode(0);
	if (stop != end() ) {
		stop++;
		while (stop != end() && *stop == 0 ) stop++; // maybe we have trailing of zeroes
		if (stop!=end()) {
			throw asn_error("extra bytes at the end");
			}
		}
	}
