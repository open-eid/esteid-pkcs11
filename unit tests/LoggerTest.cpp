#include "Logger.h"
#include "gmock/gmock.h"
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#include <strsafe.h>
#endif


using namespace std;

bool fileExist(string fileName) {
  return access(fileName.c_str(), W_OK) != -1;
}

class LoggerTest : public ::testing::Test {
private:
  string tempOriginalEnvironmentVariable;
protected:
  virtual void SetUp() {
#ifdef _WIN32
	tempOriginalEnvironmentVariable = getenv("TEMP");
#elif __APPLE__
    tempOriginalEnvironmentVariable = getenv("TMPDIR");
#endif
  }

  virtual void TearDown() {
#ifdef _WIN32
  _putenv_s("TEMP", tempOriginalEnvironmentVariable.c_str());
#elif __APPLE__
    setenv("TMPDIR", tempOriginalEnvironmentVariable.c_str(), 1);
#endif
  }
};

TEST_F(LoggerTest, getLogFilenameWithEnvironmentVariable) {
#ifdef _WIN32
  _putenv_s("TEMP", "c:\\tmp");
  ASSERT_EQ(string("c:\\tmp\\esteid-pkcs11.log"), Logger::getLogFileName());
#elif __APPLE__
  setenv("TMPDIR", "/test/tmp", 1);
  ASSERT_EQ(string("/test/tmp/esteid-pkcs11.log"), Logger::getLogFileName());
#else
  ASSERT_EQ(string("/tmp/esteid-pkcs11.log"), Logger::getLogFileName());
#endif
}

TEST_F(LoggerTest, getLogFilenameWithoutEnvironmentVariable) {
#ifdef _WIN32
  _putenv_s("TEMP", "");
  ASSERT_EQ(string("c:\\esteid-pkcs11.log"), Logger::getLogFileName());
#else
  unsetenv("TMPDIR");
  ASSERT_EQ(string("/tmp/esteid-pkcs11.log"), Logger::getLogFileName());
#endif
}

TEST_F(LoggerTest, logLine) {
  ASSERT_EQ("func() [file:3]", Logger::logLine("func", "file", 3));
}

TEST_F(LoggerTest, writeLogWhenFileDoesNotExist) {
  string logFileName = Logger::getLogFileName();
  remove(logFileName.c_str());
  ASSERT_FALSE(fileExist(logFileName));
  Logger::writeLog("1", "2", 3, "Message");
  ASSERT_FALSE(fileExist(logFileName));
}

TEST_F(LoggerTest, writeLogWhenFileExists) {
  string logFileName = Logger::getLogFileName();
  ofstream outputFile(logFileName.c_str());
  outputFile << flush;
  outputFile.close();
  ASSERT_TRUE(fileExist(logFileName));

  Logger::writeLog("1", "2", 3, "Message");
  Logger::writeLog("1", "2", 3, "Message:%i", 10);

  ifstream logFile(logFileName.c_str());
  string line;
  getline(logFile, line);
  ASSERT_EQ("1() [2:3] Message", line);
  getline(logFile, line);
  ASSERT_EQ("1() [2:3] Message:10", line);
  getline(logFile, line);
  ASSERT_EQ("", line);

  logFile.close();
  remove(logFileName.c_str());

  ASSERT_FALSE(fileExist(logFileName));
}