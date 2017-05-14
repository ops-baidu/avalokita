#!/bin/sh

set -eu

rm -rf build output && mkdir -p build output

cd thirdparty/curl-7.54.0
./configure --prefix=$(pwd)/../../output --disable-shared --disable-debug \
	--without-ssl --without-winssl --without-darwinssl --without-gnutls \
	--without-polarssl --without-mbedtls --without-cyassl --without-nss \
	--without-axtls --without-libpsl --without-libmetalink \
	--without-libssh2 --without-librtmp --without-winidn --without-libidn2 \
	--without-nghttp2 --without-zsh-functions-dir --without-ldap-lib \
	--without-lber-lib --without-gssapi --disable-rtsp
make -j 16
make install
cd -

cd thirdparty/libev-4.24
./configure --prefix=$(pwd)/../../output --disable-shared
make
make install
cd -

cd build
VER=$(git describe --tags --always --dirty | tr '-' '.')
export CMAKE_INCLUDE_PATH="$(pwd)/../output/include"
export CMAKE_LIBRARY_PATH="$(pwd)/../output/lib"
cmake -DCMAKE_INSTALL_PREFIX=/ -DVERSION="$VER" ..
make
make DESTDIR="$(pwd)/../output" install
cd -

rm -rf rpmroot && mkdir -p rpmroot/{BUILD,RPMS,SPECS,TMP}
cp avalokita.rpm.spec rpmroot/SPECS/avalokita.spec
sed -i "s/#VERSION#/${VER}/g" rpmroot/SPECS/avalokita.spec
rpmbuild --define "_topdir ${PWD}/rpmroot/" --define "_tmppath %{_topdir}/TMP" -bb rpmroot/SPECS/avalokita.spec
cp -r rpmroot/RPMS/ output

