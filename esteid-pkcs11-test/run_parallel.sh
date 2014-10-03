#!/bin/sh
pushd ../Debug
./esteid-pkcs11-test ../esteid-pkcs11-test/mariliis_AS3500006.cfg 0 &
./esteid-pkcs11-test ../esteid-pkcs11-test/igor_X0010119.cfg 2
popd
