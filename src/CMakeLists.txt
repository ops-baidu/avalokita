ADD_EXECUTABLE(avalokita main.c)
INSTALL(TARGETS avalokita RUNTIME DESTINATION bin)

if($ENV{CLION_IDE})
    INCLUDE_DIRECTORIES(BEFORE ${PROJECT_BINARY_DIR}/src)
    TARGET_LINK_LIBRARIES(avalokita m rt dl)
else()
    include(CheckFunctionExists)

    check_function_exists(prctl SYSTEM_PRCTL_FOUND)
    if(NOT SYSTEM_PRCTL_FOUND)
        message(FATAL_ERROR "your os do not support prctl().")
    endif()

    find_path(LIBEV_H NAMES ev.h)
    find_library(LIBEV_LIB NAMES ev)

    if(NOT LIBEV_H OR NOT LIBEV_LIB)
        message(FATAL_ERROR "libev not found.")
    endif()

    find_path(CURL_H NAMES curl/curl.h)
    find_library(CURL_LIB NAMES curl)

    if(NOT CURL_H OR NOT CURL_LIB)
        message(FATAL_ERROR "libcurl not found.")
    endif()

    find_path(SSL_H NAMES openssl/ssl.h)
    find_library(SSL_LIB NAMES ssl)

    if(NOT SSL_H OR NOT SSL_LIB)
        message(FATAL_ERROR "libssl not found.")
    endif()

    find_path(CRYPTO_H NAMES openssl/crypto.h)
    find_library(CRYPTO_LIB NAMES crypto)

    if(NOT CRYPTO_H OR NOT CRYPTO_LIB)
        message(FATAL_ERROR "libcrypto not found.")
    endif()

    find_path(Z_H NAMES zlib.h)
    find_library(Z_LIB NAMES z)

    if(NOT Z_H OR NOT Z_LIB)
        message(FATAL_ERROR "zlib not found.")
    endif()

    INCLUDE_DIRECTORIES(BEFORE ${PROJECT_BINARY_DIR}/src ${CURL_H} ${LIBEV_H} ${SSL_H} ${CRYPTO_H} ${Z_H})
    TARGET_LINK_LIBRARIES(avalokita ${LIBEV_LIB} ${CURL_LIB} ${SSL_LIB} ${CRYPTO_LIB} ${Z_LIB} m rt dl)
endif()
