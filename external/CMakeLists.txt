include(ExternalProject)

set(LIBSSH_GIT_TAG "libssh-0.12.0")

# LibCURL version
# Please refer to README.md for more details
set(LIBCURL_VERSION "8.18.0")

# Collected license texts of all external components
set(LICENSE_DIR "${CMAKE_BINARY_DIR}/LICENSES")

# Better String Library
ExternalProject_Add(
        bstrlib
        PREFIX ${CMAKE_BINARY_DIR}/external/.bstrlib
        INSTALL_DIR ${CMAKE_BINARY_DIR}/external
        GIT_REPOSITORY https://github.com/websnarf/bstrlib.git
        GIT_SHALLOW 1
        GIT_TAG master
        TLS_VERIFY OFF
        BUILD_IN_SOURCE 1
        UPDATE_COMMAND ""
        CONFIGURE_COMMAND ""
        BUILD_COMMAND sh -c "${CMAKE_C_COMPILER} -c bsafe.c bstraux.c bstrlib.c buniutil.c testaux.c utf8util.c"
        INSTALL_COMMAND sh -c "mkdir -p <INSTALL_DIR>/lib <INSTALL_DIR>/include"
                COMMAND sh -c "${CMAKE_AR} rv <INSTALL_DIR>/lib/bstrlib.a <BINARY_DIR>/bstraux.o <BINARY_DIR>/bstrlib.o"
                COMMAND sh -c "cp <BINARY_DIR>/bstrlib.h <BINARY_DIR>/bstraux.h  <INSTALL_DIR>/include"
                COMMAND sh -c "mkdir -p ${LICENSE_DIR}/bstrlib && cp <SOURCE_DIR>/LICENSE ${LICENSE_DIR}/bstrlib/"
)


# LibSSH
ExternalProject_Add(
        libssh
        PREFIX ${CMAKE_BINARY_DIR}/external/.libssh

        GIT_REPOSITORY https://gitlab.com/libssh/libssh-mirror.git
        GIT_TAG "${LIBSSH_GIT_TAG}"
        GIT_SHALLOW 1

        UPDATE_COMMAND ""

        # Apply suSSHi patches
        # & prevent dynlib global symbols from being restricted to functions defined by SUSSHI_API only
        PATCH_COMMAND bash -c "git apply ${CMAKE_CURRENT_LIST_DIR}/patches/libssh/${LIBSSH_GIT_TAG}.patch" &&
                      bash -c "sed -i.bak 's/HAVE_LD_VERSION_SCRIPT)/HAVE_LD_VERSION_SCRIPT_SUSSHI_OFF)/g' <SOURCE_DIR>/ConfigureChecks.cmake ; rm <SOURCE_DIR>/ConfigureChecks.cmake.bak"


        CMAKE_ARGS "-DCMAKE_C_COMPILER=clang"
        CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/external"
        CMAKE_ARGS "-DDEBUG_CALLTRACE=${LIBSSH_CALLTRACE}"
        CMAKE_ARGS "-DWITH_PCAP=${LIBSSH_PCAP}"
        CMAKE_ARGS "-DWITH_EXAMPLES=OFF"
        CMAKE_ARGS "-DWITH_GSSAPI=OFF"
        CMAKE_ARGS "-DWITH_ZLIB=ON"
        CMAKE_ARGS "-DWITH_INTERNAL_DOC=OFF"
        CMAKE_ARGS "-DWITH_MBEDTLS=OFF"
        CMAKE_ARGS "-DDEBUG_PACKET=OFF"
        CMAKE_ARGS "-DBUILD_SHARED_LIBS=OFF"

        BUILD_COMMAND bash -c "make -j"

        INSTALL_DIR ${CMAKE_BINARY_DIR}/external
        INSTALL_COMMAND sh -c "make install"

        COMMAND bash -c "cp <BINARY_DIR>/config.h <INSTALL_DIR>/include/libssh"
        COMMAND bash -c "cp <SOURCE_DIR>/include/libssh/config.h <INSTALL_DIR>/include/libssh/libssh-config.h"
        COMMAND bash -c "cp <SOURCE_DIR>/include/libssh/{auth.h,buffer.h,buffer-struct.h,channels.h,curve25519.h,crypto.h,dh.h,ecdh.h,ed25519.h,kex.h,legacy.h,libcrypto.h,libgcrypt.h,libmbedcrypto.h,libssh.h,messages.h,misc.h,packet.h,pcap.h,pki.h,poll.h,priv.h,session.h,sntrup761.h,socket.h,ssh2.h,string.h,wrapper.h} <INSTALL_DIR>/include/libssh"

        # Ship the suSSHi patch alongside the license: it documents that the
        # statically linked libSSH is modified (LGPL-2.1 section 2)
        COMMAND bash -c "mkdir -p ${LICENSE_DIR}/libssh && cp <SOURCE_DIR>/COPYING <SOURCE_DIR>/AUTHORS ${LICENSE_DIR}/libssh/"
        COMMAND bash -c "cp ${CMAKE_CURRENT_LIST_DIR}/patches/libssh/${LIBSSH_GIT_TAG}.patch ${LICENSE_DIR}/libssh/"
)

# LibCURL
# --> We cannot use the OS libcurl because it is compiled with SFTP support which conflicts with libSSH
# Please refer to README.md for more details
ExternalProject_Add(
        libcurl
        PREFIX ${CMAKE_BINARY_DIR}/external/.libcurl
        DOWNLOAD_EXTRACT_TIMESTAMP True
        URL "https://curl.haxx.se/download/curl-${LIBCURL_VERSION}.tar.gz"
        INSTALL_DIR ${CMAKE_BINARY_DIR}/external
        BUILD_COMMAND bash -c "make -j"
        BUILD_IN_SOURCE 1
        CONFIGURE_COMMAND sh -c "./configure --enable-versioned-symbols --prefix=<INSTALL_DIR> --disable-ftp --enable-libcurl-option --with-openssl --disable-shared"
        INSTALL_COMMAND sh -c "make install"

        # curl lists COPYING in EXTRA_DIST only, its make install does not ship it
        COMMAND sh -c "mkdir -p ${LICENSE_DIR}/curl && cp <SOURCE_DIR>/COPYING ${LICENSE_DIR}/curl/"
)

# IPBT
ExternalProject_Add(
        ipbt
        PREFIX ${CMAKE_BINARY_DIR}/external/.ipbt
        DOWNLOAD_EXTRACT_TIMESTAMP True
        URL https://www.chiark.greenend.org.uk/~sgtatham/ipbt/ipbt.tar.gz
        BUILD_IN_SOURCE 1
        INSTALL_DIR ${CMAKE_BINARY_DIR}/external
        # CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix <INSTALL_DIR> --program-prefix 'susshi-'
        CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/external"
        BUILD_COMMAND bash -c "make -j"
        INSTALL_COMMAND sh -c "make install"
        COMMAND bash -c "mv <INSTALL_DIR>/bin/ipbt <INSTALL_DIR>/bin/susshi-ipbt"

        # ipbt only installs the binary and its man page, so copy LICENCE ourselves
        COMMAND bash -c "mkdir -p ${LICENSE_DIR}/ipbt && cp <SOURCE_DIR>/LICENCE ${LICENSE_DIR}/ipbt/"
)

# LibUnity
ExternalProject_Add(
        unity_external
        GIT_REPOSITORY  https://github.com/ThrowTheSwitch/Unity.git
        GIT_TAG         master          # or pin to a specific tag like v2.5.2
        CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/external
        UPDATE_DISCONNECTED TRUE        # avoid re-fetching on every build
)

# Unity uses the default install command, so the license needs its own step.
ExternalProject_Add_Step(unity_external copy_license
        COMMAND bash -c "mkdir -p ${LICENSE_DIR}/unity && cp <SOURCE_DIR>/LICENSE.txt ${LICENSE_DIR}/unity/"
        DEPENDEES build
        DEPENDERS install
)