if (LINUX)
    project(susshi-who C)

    # Sources
    set(susshi-who_SRCS
            susshi-who.c
            )

    # Executable target
    add_executable(susshi-who ${susshi-who_SRCS})

    # Used Libraries

    #- libcrypto (used for crypto functions within susshi, binding not required for libssh)
    find_library(LIBCRYPTO crypto REQUIRED)
    target_link_libraries(susshi-who ${LIBCRYPTO})

    #- (lib)resolv
    find_library(LIBRESOLV resolv REQUIRED)
    target_link_libraries(susshi-who ${LIBRESOLV})

    #- libbsd
    find_library(LIBBSD bsd REQUIRED)
    target_link_libraries(susshi-who ${LIBBSD})

    #- real-time library
    target_link_libraries(susshi-who rt)

    #- libproc2
    find_library(LIBPROC2 proc2 REQUIRED)
    target_link_libraries(susshi-who ${LIBPROC2})

    #- suSSHi shared functions
    target_link_libraries(susshi-who ${CMAKE_BINARY_DIR}/src/shared/libsusshi-shared.a)

    #- libssh [static]
    target_link_libraries(susshi-who ${CMAKE_BINARY_DIR}/external/lib/libssh.a)

    #- zlib (required by static libssh)
    find_library(LIBZ z REQUIRED)
    target_link_libraries(susshi-who ${LIBZ})

    #- Better String Library (build localy within suSSHi build process, see <suSSHi-root>/external folder)
    target_link_libraries(susshi-who ${CMAKE_BINARY_DIR}/external/lib/bstrlib.a)

    install(TARGETS susshi-who DESTINATION bin)

endif (LINUX)
