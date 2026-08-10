project(susshi-proxyd C)

# Sources
set(susshi-proxyd_SRCS
        auth-gateway.c
        connect-target.c
        helpers.c
        libssh-helpers.c
        log.c
        master-loop.c
        monitor-daemon.c
        proxy-cfg.c
        session.c
        session-loop.c
        signal.c
        main.c
)

# Executable target
add_executable(susshi-proxyd ${susshi-proxyd_SRCS})

# Used Libraries

#- libcrypto (used for crypto functions within susshi, binding not required for libssh)
find_library(LIBCRYPTO crypto REQUIRED)
target_link_libraries(susshi-proxyd ${LIBCRYPTO})

#- libssh [static]
target_link_libraries(susshi-proxyd ${CMAKE_BINARY_DIR}/external/lib/libssh.a)

#- zlib (required by static libssh)
find_library(LIBZ z REQUIRED)
target_link_libraries(susshi-proxyd ${LIBZ})

#- real-time library
find_library(LIBRT rt REQUIRED)
target_link_libraries(susshi-proxyd ${LIBRT})

#- libmicrohttp
find_library(MICROHTTPD microhttpd REQUIRED)
target_link_libraries(susshi-proxyd ${MICROHTTPD})

#- libutil
find_library(LIBUTIL util REQUIRED)
target_link_libraries(susshi-proxyd ${LIBUTIL})

#- libpcre2
find_library(LIBPCRE2 pcre2-8 REQUIRED)
target_link_libraries(susshi-proxyd ${LIBPCRE2})

#- (lib)jansson
find_library(LIBJANSSON jansson REQUIRED)
target_link_libraries(susshi-proxyd ${LIBJANSSON})

#- (lib)resolv
find_library(LIBRESOLV resolv REQUIRED)
target_link_libraries(susshi-proxyd ${LIBRESOLV})

#- libbsd
if (LINUX)
    find_library(LIBBSD bsd REQUIRED)
    target_link_libraries(susshi-proxyd ${LIBBSD})
endif (LINUX)

#- suSSHi shared functions
target_link_libraries(susshi-proxyd ${CMAKE_BINARY_DIR}/src/shared/libsusshi-shared.a)

#- Better String Library (build localy within suSSHi build process, see <suSSHi-root>/external folder)
target_link_libraries(susshi-proxyd ${CMAKE_BINARY_DIR}/external/lib/bstrlib.a)
add_dependencies(susshi-proxyd bstrlib)

install(TARGETS susshi-proxyd DESTINATION sbin)