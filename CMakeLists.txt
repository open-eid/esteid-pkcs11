cmake_minimum_required(VERSION 2.8)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
project(esteid-pkcs11)
set(ENABLE_VISIBILITY "YES")
include(VersionInfo)
include(GNUInstallDirs)
enable_testing()
#set(CMAKE_FIND_ROOT_PATH ${CMAKE_OSX_SYSROOT})

find_package(OpenSSL REQUIRED)

if(APPLE)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -Wno-c++11-narrowing")
endif()

if(UNIX AND NOT APPLE)
    find_package(PCSCLite REQUIRED)
endif()

add_subdirectory(googlemock)
if(NOT GMOCK_ROOT)
  set(GMOCK_ROOT "googlemock")
endif()
if(NOT GTEST_ROOT)
  set(GTEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/gtest)
endif()

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${OPENSSL_INCLUDE_DIR}
  ${PCSCLITE_INCLUDE_DIR}
  ${GTEST_ROOT}
  ${GTEST_ROOT}/include
  ${GTEST_ROOT}/include/gtest
  ${GMOCK_ROOT}
  ${GMOCK_ROOT}/include
)
add_subdirectory(smartcardpp)

if(WIN32)
    add_definitions(/DCRYPTOKI_EXPORTS)
endif()

add_library(esteid-pkcs11 MODULE
    esteidpkcs11.cpp
    esteidpkcs11.rc
    PKCS11Context.cpp
    precompiled.cpp
    Logger.cpp
    utility/asnCertificate.cpp
    utility/asnObject.cpp
)

add_library(esteid-pkcs11-onepin MODULE
    esteidpkcs11.cpp
    esteidpkcs11.rc
    PKCS11Context.cpp
    OnePinPKCS11Context.cpp
    precompiled.cpp
    Logger.cpp
    utility/asnCertificate.cpp
    utility/asnObject.cpp
)

add_executable(runUnitTests
    esteidpkcs11.cpp
    esteidpkcs11.rc
    PKCS11Context.cpp
    OnePinPKCS11Context.cpp
    precompiled.cpp
    Logger.cpp
    utility/asnCertificate.cpp
    utility/asnObject.cpp
    unit\ tests/esteid-unit-test.cpp
    unit\ tests/LoggerTest.cpp
    unit\ tests/PKCS11Context_C_GetInfo_Test.cpp
    unit\ tests/PKCS11Context_C_GetSlotList_Test.cpp
    unit\ tests/PKCS11Context_C_GetSlotInfo_Test.cpp
    unit\ tests/PKCS11Context_C_GetMechanismList_Test.cpp
    unit\ tests/PKCS11Context_C_GetMechanismInfo_Test.cpp
    unit\ tests/PKCS11Context_C_InitToken_Test.cpp
    unit\ tests/PKCS11Context_C_GetTokenInfo_Test.cpp
    unit\ tests/PKCS11Context_C_OpenSession_Test.cpp
    unit\ tests/PKCS11Context_C_Login_Test.cpp
    unit\ tests/PKCS11Context_C_SignInit_Test.cpp
    unit\ tests/PKCS11Context_C_Sign_Test.cpp
    unit\ tests/PKCS11Context_C_SignFinal_Test.cpp
    unit\ tests/PKCS11Context_C_DecryptInit_Test.cpp
    unit\ tests/PKCS11Context_C_Decrypt_Test.cpp
    unit\ tests/OnePinPKCS11Context_C_GetSlotList_Test.cpp
    unit\ tests/OnePinPKCS11Context_C_GetSlotInfo_Test.cpp
    unit\ tests/main.cpp
)

if(CMAKE_COMPILER_IS_GNUCC OR __COMPILER_GNU)
  set_target_properties(esteid-pkcs11 esteid-pkcs11-onepin smartcardpp runUnitTests PROPERTIES COMPILE_FLAGS "-fPIC")
  set_target_properties(runUnitTests PROPERTIES COMPILE_FLAGS "--coverage -O0 -fPIC")
  set_target_properties(runUnitTests PROPERTIES LINK_FLAGS "--coverage")
endif()

set_target_properties(esteid-pkcs11 esteid-pkcs11-onepin PROPERTIES PREFIX "")
target_link_libraries(esteid-pkcs11 smartcardpp ${OPENSSL_LIBRARIES})
target_link_libraries(esteid-pkcs11-onepin smartcardpp ${OPENSSL_LIBRARIES})

set_target_properties(esteid-pkcs11-onepin PROPERTIES COMPILE_DEFINITIONS "ONE_PIN")

set_target_properties(runUnitTests PROPERTIES COMPILE_DEFINITIONS "TEST_MODE")
target_link_libraries(runUnitTests gmock gmock_main smartcardpp ${OPENSSL_LIBRARIES})

Add_Custom_Command (TARGET runUnitTests POST_BUILD COMMAND ./runUnitTests --gtest_output=xml:test_report.xml)
#Add_Custom_Command (TARGET runUnitTests POST_BUILD COMMAND gcovr  --filter='.*/PKCS11Context.cpp|.*/Logger.cpp' -x -o coverage.xml)
#execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ../../coverage)
#Add_Custom_Command (TARGET runUnitTests POST_BUILD COMMAND gcovr  --filter='.*/PKCS11Context.cpp|.*/Logger.cpp' --html --html-details -o ../../coverage/coverage.html)

install(TARGETS esteid-pkcs11 esteid-pkcs11-onepin LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

if(APPLE)
   add_custom_target(installer
        COMMENT "Creating installer"
        COMMAND codesign -f -s \"$$SIGNER\"  $<TARGET_FILE:esteid-pkcs11> $<TARGET_FILE:esteid-pkcs11-onepin>
        COMMAND mkdir -p "root/${CMAKE_INSTALL_LIBDIR}"
        COMMAND cp $<TARGET_FILE:esteid-pkcs11> $<TARGET_FILE:esteid-pkcs11-onepin> "root/${CMAKE_INSTALL_LIBDIR}"
        COMMAND pkgbuild --root root --sign \"$$SIGNER\" --version "${VERSION}$ENV{VER_SUFFIX}"
                --identifier "ee.ria.${PROJECT_NAME}" ${PROJECT_NAME}_${VERSION}$ENV{VER_SUFFIX}.pkg
    )
endif()
