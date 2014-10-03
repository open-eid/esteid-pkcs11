#include <unistd.h>
#include <pkcs11.h>
#include <map>

using namespace std;

extern CK_FUNCTION_LIST_PTR fl;

extern map<string, string> config;
extern int slotId;
char* nullTerminatedString(char*, unsigned char *, size_t );
unsigned char *hex2bin(const char *);


