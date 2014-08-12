#!/bin/sh

CMAKE_PATH="$(pwd)/../../noah/thirdparty/cmake/output"
LIBEV_PATH="$(pwd)/../../noah/thirdparty/libev/output"
LIBCURL_PATH="$(pwd)/../../noah/thirdparty/libcurl/output"
OPENSSL_PATH="$(pwd)/../../noah/thirdparty/openssl/output/usr"
ZLIB_PATH="$(pwd)/../../noah/thirdparty/zlib/output/usr"

PATH="$CMAKE_PATH/bin:$LIBEV_PATH/bin:$LIBCURL_PATH/bin:$OPENSSL_PATH/bin:$ZLIB_PATH/bin:$PATH"
export CMAKE_INCLUDE_PATH="$LIBEV_PATH/include:$LIBCURL_PATH/include:$OPENSSL_PATH/include:$ZLIB_PATH/include"
export CMAKE_LIBRARY_PATH="$LIBEV_PATH/lib:$LIBCURL_PATH/lib:$OPENSSL_PATH/lib:$ZLIB_PATH/lib"

cmake .
make
make DESTDIR="$(pwd)/output" install

