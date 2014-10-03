#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "esteid-pkcs11-test.h"

char* nullTerminatedString(char* resultBuffer, unsigned char *initialValue, size_t bufferSize) {
  memcpy(resultBuffer, initialValue, bufferSize);
  resultBuffer[bufferSize] = '\0';
  return resultBuffer;
}

unsigned char *hex2bin(const char *hex) {
  int binLength;
  unsigned char *bin;
  unsigned char *c;
  char *h;
  int i = 0;

  binLength = strlen(hex) / 2;
  bin = (unsigned char *)malloc(binLength);
  c = bin;
  h = (char *)hex;
  while (*h) {
    int x;
    sscanf(h, "%2X", &x);
    *c = x;
    c++;
    h += 2;
    i++;
  }
  return bin;
}
