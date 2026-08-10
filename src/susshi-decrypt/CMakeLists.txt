project(susshi-decrypt C)

# Sources
set(susshi-decrypt_SRCS
        susshi-decrypt.c
)

# Executable target
add_executable(susshi-decrypt ${susshi-decrypt_SRCS})

# Used Libraries

#- suSSHi shared functions (includes log-enc.c with all crypto primitives)
target_link_libraries(susshi-decrypt ${CMAKE_BINARY_DIR}/src/shared/libsusshi-shared.a)

#- libssh [static] (used by susshi_log_enc_read_privkey for key import)
target_link_libraries(susshi-decrypt ${CMAKE_BINARY_DIR}/external/lib/libssh.a)

#- zlib (required by static libssh)
find_library(LIBZ z REQUIRED)
target_link_libraries(susshi-decrypt ${LIBZ})

#- libcrypto (used by static libssh and EVP key extraction in log-enc)
find_library(LIBCRYPTO crypto REQUIRED)
target_link_libraries(susshi-decrypt ${LIBCRYPTO})

#- libsodium (used by log-enc for secretstream and box crypto)
find_library(LIBSODIUM sodium REQUIRED)
target_link_libraries(susshi-decrypt ${LIBSODIUM})

#- libjansson (used by log-enc for .enc sidecar JSON parsing)
find_library(LIBJANSSON jansson REQUIRED)
target_link_libraries(susshi-decrypt ${LIBJANSSON})

#- libbsd (required by wrappers.c for setproctitle on Linux)
if (LINUX)
    find_library(LIBBSD bsd REQUIRED)
    target_link_libraries(susshi-decrypt ${LIBBSD})
endif (LINUX)

#- Better String Library
target_link_libraries(susshi-decrypt ${CMAKE_BINARY_DIR}/external/lib/bstrlib.a)
add_dependencies(susshi-decrypt bstrlib)

install(TARGETS susshi-decrypt DESTINATION bin)
