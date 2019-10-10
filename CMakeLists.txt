cmake_minimum_required(VERSION 3.14)
project(http2 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(src_crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/aes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/aesni.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/arc4.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/asn1parse.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/asn1write.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/base64.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/bignum.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/blowfish.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/camellia.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ccm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/cipher.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/cipher_wrap.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/cmac.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ctr_drbg.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/des.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/dhm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ecdh.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ecdsa.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ecjpake.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ecp.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ecp_curves.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/entropy.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/entropy_poll.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/error.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/gcm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/havege.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/hmac_drbg.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/md.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/md2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/md4.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/md5.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/md_wrap.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/memory_buffer_alloc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/net_sockets.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/oid.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/padlock.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/pem.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/pk.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/pkcs12.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/pkcs5.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/pkparse.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/pkwrite.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/pk_wrap.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/platform.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ripemd160.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/rsa.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/sha1.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/sha256.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/sha512.c

        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/threading.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/timing.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/version.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/version_features.c

        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/xtea.c
        )
set(src_x509
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/certs.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/pkcs11.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/x509.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/x509write_crt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/x509write_csr.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/x509_create.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/x509_crl.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/x509_crt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/x509_csr.c)
set(src_tls
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/debug.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ssl_cache.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ssl_ciphersuites.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ssl_cli.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ssl_cookie.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ssl_srv.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ssl_ticket.c
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ssl_tls.c
        )
#-Wdocumentation -Wno-documentation-deprecated-sync
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations -Wmissing-prototypes -Wunreachable-code")
set(mbedtls_static_target "mbedtls")
set(mbedx509_static_target "mbedx509")
set(mbedcrypto_static_target "mbedcrypto")

set(libs ${libs} ws2_32)

add_library(${mbedcrypto_static_target} STATIC ${src_crypto})
target_link_libraries(${mbedcrypto_static_target} ${libs})

add_library(${mbedx509_static_target} STATIC ${src_x509})
target_link_libraries(${mbedx509_static_target} ${libs} ${mbedcrypto_static_target})

add_definitions(-D_WIN32)
add_library(${mbedtls_static_target} STATIC ${src_tls})
target_link_libraries(${mbedtls_static_target} ${libs} ${mbedx509_static_target})

include_directories(PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include)
link_libraries(mbedtls)
add_executable(http2 main.c)