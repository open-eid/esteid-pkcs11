@echo off

IF NOT EXIST build\NUL GOTO NO_BUILD_DIR
del build

:NO_BUILD_DIR

mkdir build
pushd build

cmake.exe .. -G "NMake Makefiles" -DCMAKE_VERBOSE_MAKEFILE="ON" -DOPENSSL_ROOT_DIR="C:/OpenSSL-Win32" -DLIB_EAY_DEBUG="C:/OpenSSL-Win32/lib/VC/static/libeay32MTd.lib" -DLIB_EAY_RELEASE="C:/OpenSSL-Win32/lib/VC/static/libeay32MT.lib" -DCMAKE_CXX_FLAGS_DEBUG:STRING="/D_DEBUG /MTd /Zi /Ob0 /Od /RTC1" -DCMAKE_C_FLAGS_DEBUG:STRING="/D_DEBUG /MTd /Zi /Ob0 /Od /RTC1" -DGMOCK_ROOT=googlemock -DICONV_LIBRARIES="C:/Program Files (x86)/GnuWin32/lib/libiconv.lib" -DICONV_INCLUDE_DIR="C:/Program Files (x86)/GnuWin32/include"
nmake

popd