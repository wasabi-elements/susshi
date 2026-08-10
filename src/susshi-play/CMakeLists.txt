project(susshi-play C)

# Sources
set(susshi-play_SRCS
        susshi-play.c
        )

# Executable target
add_executable(susshi-play ${susshi-play_SRCS})

# Used Libraries

#- suSSHi shared functions (includes log-enc.c with all crypto primitives)
target_link_libraries(susshi-play ${CMAKE_BINARY_DIR}/src/shared/libsusshi-shared.a)

#- libssh [static] (used by susshi_log_enc_read_privkey for key import)
target_link_libraries(susshi-play ${CMAKE_BINARY_DIR}/external/lib/libssh.a)

#- zlib (required by static libssh)
find_library(LIBZ z REQUIRED)
target_link_libraries(susshi-play ${LIBZ})

#- libcrypto (used by static libssh and EVP key extraction in log-enc)
find_library(LIBCRYPTO crypto REQUIRED)
target_link_libraries(susshi-play ${LIBCRYPTO})

#- libsodium (used by log-enc for secretstream and box crypto)
find_library(LIBSODIUM sodium REQUIRED)
target_link_libraries(susshi-play ${LIBSODIUM})

#- libjansson (used by log-enc for .enc sidecar JSON parsing)
find_library(LIBJANSSON jansson REQUIRED)
target_link_libraries(susshi-play ${LIBJANSSON})

#- libbsd (required by wrappers.c for setproctitle on Linux)
if (LINUX)
    find_library(LIBBSD bsd REQUIRED)
    target_link_libraries(susshi-play ${LIBBSD})
endif (LINUX)

#- Better String Library (build locally within suSSHi build process, see <suSSHi-root>/external folder)
target_link_libraries(susshi-play ${CMAKE_BINARY_DIR}/external/lib/bstrlib.a)
add_dependencies(susshi-play bstrlib)

install(TARGETS susshi-play DESTINATION bin)
