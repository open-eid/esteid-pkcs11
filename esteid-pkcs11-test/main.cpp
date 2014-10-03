#include <iostream>
#include <dlfcn.h>
#include <pkcs11.h>
#include <gmock/gmock.h>
#include <fstream>
#include "esteid-pkcs11-test.h"

using namespace std;

CK_FUNCTION_LIST_PTR fl;
map<string, string> config;
int slotId = 0;
void parseConfig(string);

void *loadModule(string);

int main(int argc, char *argv[]) {

  if(argc < 2) {
    cout << "Usage:\n\testeid-pkcs11-test <configuration file> <slotId>\n";
    return 1;
  }
  if(argc >= 3) {
    slotId = atoi(argv[2]);
  }

  cout << "Using slot: " << slotId << "\n";
  parseConfig(argv[1]);
  void *library = loadModule(config["modulePath"]);
  if (!library) return 2;

  CK_C_INITIALIZE_ARGS init_args;
  memset(&init_args, 0x0, sizeof(init_args));
  init_args.flags = CKF_OS_LOCKING_OK;

  CK_RV initialization_result = fl->C_Initialize(&init_args);
  if (initialization_result != CKR_OK) {
    cerr << "C_Initialize failed";
    dlclose(library);
    return 3;
  }

  ::testing::InitGoogleMock(&argc, argv);
  int test_result = RUN_ALL_TESTS();

  fl->C_Finalize(NULL_PTR);
  dlclose(library);
  return test_result;
}

void parseConfig(string configFileName) {
  cout << "Parsing configuration file: " << configFileName << "\n";
  ifstream configFileStream(configFileName);
  if(!configFileStream){
    cout << "Configuration file not found\n";
    throw runtime_error("Configuration file not found");
  }

  std::string line;
  while(getline(configFileStream, line)) {
    std::istringstream iss(line);
    string key, value;
    getline(iss, key, '=');
    getline(iss, value, '=');
    config[key] = (value[0] != '"') ? value : value.substr(1, value.length() - 2);
  }
}


void *loadModule(string moduleName) {
  void *library = dlopen(moduleName.c_str(), RTLD_LOCAL | RTLD_NOW);
  if (!library) {
    cerr << "\033[1;31mFailed to load module: " << moduleName << "\033[0m\n";
    return NULL;
  }

  cout << "Loaded module: " << moduleName << "\n";

  CK_C_GetFunctionList GetFunctionList = (CK_C_GetFunctionList) dlsym(library, "C_GetFunctionList");
  const char *error = dlerror();
  if (error) {
    cerr << "Cannot load symbol 'hello': " << error << '\n';
    dlclose(library);
    return NULL;
  }
  GetFunctionList(&fl);// TODO: add error handling

  return library;
}

