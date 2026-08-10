project(susshid C)

# Sources
set(susshid_SRCS
        auth-client.c
        auth-pubkey-agent.c
        auth-target.c
        auth-proxy.c
        chef.c
        chef-remote.c
        connect-target.c
        connect-proxy.c
        helpers.c
        hooks.c
        hostkeys-update.c
        inspect-channel.c
        inspect-packet.c
        inspect-ossh-agent.c
        inspect-scp.c
        inspect-sftp.c
        inspect-tcp.c
        inspect-unixsock.c
        inspect-x11.c
        libssh-helpers.c
        log.c
        log-session.c
        log-session-enc.c
        master-loop.c
        monitor-daemon.c
        report.c
        report-daemon.c
        rsyslog.c
        session.c
        session-loop.c
        shell.c
        shell-loop.c
        sic.c
        signal.c
        subscription.c
        susshid-main.c
        susshi-cfg.c
)

# Executable target
add_executable(susshid ${susshid_SRCS} main.c)

# Used Libraries

#- libcrypto (used for crypto functions within susshi, binding not required for libssh)
find_library(LIBCRYPTO crypto REQUIRED)
target_link_libraries(susshid ${LIBCRYPTO})

#- libssh [static]
target_link_libraries(susshid ${CMAKE_BINARY_DIR}/external/lib/libssh.a)

#- zlib (required by static libssh)
find_library(LIBZ z REQUIRED)
target_link_libraries(susshid ${LIBZ})

#- real-time library
find_library(LIBRT rt REQUIRED)
target_link_libraries(susshid ${LIBRT})

#- (lib)curl [static]
# --> We cannot use the OS libcurl because it is compiled with SFTP support which conflicts with libSSH
target_link_libraries(susshid ${CMAKE_BINARY_DIR}/external/lib/libcurl.a)

#- libidn2 (required by static curl)
find_library(LIBIDN2 idn2 REQUIRED)
target_link_libraries(susshid ${LIBIDN2})

#- libpsl (required by static curl)
find_library(LIBPSL psl REQUIRED)
target_link_libraries(susshid ${LIBPSL})

#- openssl (required by static curl and static libssh)
find_library(LIBSSL ssl REQUIRED)
target_link_libraries(susshid ${LIBSSL})

#- libproc2
find_library(LIBPROC2 proc2 REQUIRED)
target_link_libraries(susshid ${LIBPROC2})

#- libmicrohttp
find_library(MICROHTTPD microhttpd REQUIRED)
target_link_libraries(susshid ${MICROHTTPD})

#- libutil
find_library(LIBUTIL util REQUIRED)
target_link_libraries(susshid ${LIBUTIL})

#- libpcre2
find_library(LIBPCRE2 pcre2-8 REQUIRED)
target_link_libraries(susshid ${LIBPCRE2})

#- libpcap
find_library(LIBPCAP pcap REQUIRED)
target_link_libraries(susshid ${LIBPCAP})

#- libsodium
find_library(LIBSODIUM sodium REQUIRED)
target_link_libraries(susshid ${LIBSODIUM})

#- libedit
find_library(LIBEDIT edit REQUIRED)
target_link_libraries(susshid ${LIBEDIT})

#- libtermcap
find_library(LIBTERMCAP termcap REQUIRED)
target_link_libraries(susshid ${LIBTERMCAP})

#- (lib)jansson
find_library(LIBJANSSON jansson REQUIRED)
target_link_libraries(susshid ${LIBJANSSON})

#- (lib)resolv
find_library(LIBRESOLV resolv REQUIRED)
target_link_libraries(susshid ${LIBRESOLV})

#- libbsd
if (LINUX)
    find_library(LIBBSD bsd REQUIRED)
    target_link_libraries(susshid ${LIBBSD})
endif (LINUX)

#- suSSHi shared functions
target_link_libraries(susshid ${CMAKE_BINARY_DIR}/src/shared/libsusshi-shared.a)

#- Better String Library (build localy within suSSHi build process, see <suSSHi-root>/external folder)
target_link_libraries(susshid ${CMAKE_BINARY_DIR}/external/lib/bstrlib.a)
add_dependencies(susshid bstrlib)

install(TARGETS susshid DESTINATION sbin)

add_library(susshid-tests STATIC ${susshid_SRCS})
