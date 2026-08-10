if (LINUX)
    project(susshi-last C)

    # Sources
    set(susshi-last_SRCS
            susshi-last.c
            )

    # Executable target
    add_executable(susshi-last ${susshi-last_SRCS})

    # Used Libraries

    #- libcrypto (used for crypto functions within susshi, binding not required for libssh)
    find_library(LIBCRYPTO crypto REQUIRED)
    target_link_libraries(susshi-last ${LIBCRYPTO})

    #- (lib)resolv
    find_library(LIBRESOLV resolv REQUIRED)
    target_link_libraries(susshi-last ${LIBRESOLV})

    #- libbsd
    find_library(LIBBSD bsd REQUIRED)
    target_link_libraries(susshi-last ${LIBBSD})

    #- real-time library
    target_link_libraries(susshi-last rt)

    #- libproc2
    find_library(LIBPROC2 proc2 REQUIRED)
    target_link_libraries(susshi-last ${LIBPROC2})

    #- suSSHi shared functions
    target_link_libraries(susshi-last ${CMAKE_BINARY_DIR}/src/shared/libsusshi-shared.a)

    #- libssh [static]
    target_link_libraries(susshi-last ${CMAKE_BINARY_DIR}/external/lib/libssh.a)

    #- zlib (required by static libssh)
    find_library(LIBZ z REQUIRED)
    target_link_libraries(susshi-last ${LIBZ})

    #- Better String Library (build localy within suSSHi build process, see <suSSHi-root>/external folder)
    target_link_libraries(susshi-last ${CMAKE_BINARY_DIR}/external/lib/bstrlib.a)

    install(TARGETS susshi-last DESTINATION bin)

endif (LINUX)
