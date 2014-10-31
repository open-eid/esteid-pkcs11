# EstEID PKCS11 Module

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority

## Building
[![Build Status](https://travis-ci.org/open-eid/esteid-pkcs11.svg?branch=master)](https://travis-ci.org/open-eid/esteid-pkcs11)

### Ubuntu

1. Install dependencies

        sudo apt-get install cmake libpcsclite-dev libssl-dev

2. Fetch the source

        git clone --recursive https://github.com/open-eid/esteid-pkcs11
        cd esteid-pkcs11

3. Configure

        mkdir build
        cd build
        cmake ..

4. Build

        make

5. Install

        sudo make install

6. Execute

        firefox
        
### OSX

1. Install dependencies from [http://www.cmake.org](http://www.cmake.org)


2. Fetch the source

        git clone --recursive https://github.com/open-eid/esteid-pkcs11
        cd esteid-pkcs11

3. Configure

        mkdir build
        cd build
        cmake ..

4. Build

        make

5. Install

        sudo make install

6. Execute

        open /Application/Firefox.app

## Support
Official builds are provided through official distribution point [installer.id.ee](https://installer.id.ee). If you want support, you need to be using official builds.

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
