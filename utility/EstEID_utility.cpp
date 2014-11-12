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

#include "EstEID_utility.h"
#include <iconv.h>
#include <string.h>

void cp1250_to_utf8(char *out, char *in) {
  size_t inlen = strlen(in) + 1;
  size_t outlen = strlen(in) * 2 + 1;
  iconv_t conv = iconv_open("UTF-8", "CP1250");
#ifdef _WIN32
  const char* i = in;
  iconv(conv, &i, &inlen, &out, &outlen);
#else
  iconv(conv, &in, &inlen, &out, &outlen);
#endif
  iconv_close(conv);
}
