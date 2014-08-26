#!/bin/sh

[ -z "${SCMPF_MODULE_VERSION}" ] && {
    SCMPF_MODULE_VERSION=1.0.0.0
}

CMAKE_PATH="$(pwd)/../../noah/thirdparty/cmake/output"
LIBEV_PATH="$(pwd)/../../noah/thirdparty/libev/output"
LIBCURL_PATH="$(pwd)/../../noah/thirdparty/libcurl/output"
OPENSSL_PATH="$(pwd)/../../noah/thirdparty/openssl/output/usr"
ZLIB_PATH="$(pwd)/../../noah/thirdparty/zlib/output/usr"

PATH="$CMAKE_PATH/bin:$LIBEV_PATH/bin:$LIBCURL_PATH/bin:$OPENSSL_PATH/bin:$ZLIB_PATH/bin:$PATH"
export CMAKE_INCLUDE_PATH="$LIBEV_PATH/include:$LIBCURL_PATH/include:$OPENSSL_PATH/include:$ZLIB_PATH/include"
export CMAKE_LIBRARY_PATH="$LIBEV_PATH/lib:$LIBCURL_PATH/lib:$OPENSSL_PATH/lib:$ZLIB_PATH/lib"

rm -rf build output && mkdir -p build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/ ..
make
make DESTDIR="$(pwd)/../output" install
cd -

cd output
cp -r ../tools .
rm -rf tools/.svn
mkdir avalokita-${SCMPF_MODULE_VERSION}
cp -r bin avalokita-${SCMPF_MODULE_VERSION}
tar --owner=0 --group=0 -czvf avalokita.tgz avalokita-${SCMPF_MODULE_VERSION}
ln avalokita.tgz avalokita-${SCMPF_MODULE_VERSION}.tgz
rm -rf avalokita-${SCMPF_MODULE_VERSION}
cd -

mkdir -p rpmroot/{BUILD,RPMS,SOURCES,SPECS,SRPMS,TMP}
cp output/avalokita.tgz rpmroot/SOURCES
cp avalokita.rpm.spec rpmroot/SPECS/avalokita.spec
sed -i "s/#VERSION#/${SCMPF_MODULE_VERSION}/g" rpmroot/SPECS/avalokita.spec
rpmbuild --define "_topdir ${PWD}/rpmroot/" --define "_tmppath %{_topdir}/TMP" -bb rpmroot/SPECS/avalokita.spec
cp -r rpmroot/RPMS/ output
rm -rf rpmroot

mkdir -p debroot/control
echo 2.0 > debroot/debian-binary
cp avalokita.deb.control debroot/control/control
sed -i "s/#VERSION#/${SCMPF_MODULE_VERSION}/g" debroot/control/control

mkdir -p debroot/data/opt/avalokita/bin
install -m 755 output/bin/avalokita debroot/data/opt/avalokita/bin/

cd debroot
find data -type f | xargs md5sum | sed 's/  data\//  /g' > control/md5sums
chmod 0644 control/*

cd control
tar --owner=0 --group=0 -czvf ../control.tar.gz *
cd -

cd data
tar --owner=0 --group=0 -czvf ../data.tar.gz *
cd -

ar r avalokita_${SCMPF_MODULE_VERSION}-1_amd64.deb debian-binary control.tar.gz data.tar.gz
mkdir -p ../output/DEBS
cp avalokita_${SCMPF_MODULE_VERSION}-1_amd64.deb ../output/DEBS

cd ..
rm -rf debroot
