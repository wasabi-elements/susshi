project(susshi-suite-tests C)

include_directories(${CMAKE_SOURCE_DIR}/external/include)

find_library(LIBCRYPTO crypto REQUIRED)
find_library(LIBRESOLV resolv REQUIRED)
find_library(LIBBSD bsd REQUIRED)
find_library(LIBPROC2 proc2 REQUIRED)
find_library(LIBZ z REQUIRED)
find_library(LIBIDN2 idn2 REQUIRED)
find_library(LIBPSL psl REQUIRED)
find_library(LIBSSL ssl REQUIRED)
find_library(MICROHTTPD microhttpd REQUIRED)
find_library(LIBUTIL util REQUIRED)
find_library(LIBPCRE2 pcre2-8 REQUIRED)
find_library(LIBPCAP pcap REQUIRED)
find_library(LIBEDIT edit REQUIRED)
find_library(LIBTERMCAP termcap REQUIRED)
find_library(LIBJANSSON jansson REQUIRED)
find_library(LIBRESOLV resolv REQUIRED)
find_library(LIBSODIUM resolv REQUIRED)

function(add_susshi_test source_file)
    get_filename_component(target_name ${source_file} NAME_WE)

    get_filename_component(folder_name ${CMAKE_CURRENT_SOURCE_DIR} NAME)

    cmake_parse_arguments(ARG "" "" "SOURCES;LIBRARIES" ${ARGN})
    # ARG_SOURCES   -> additional source files
    # ARG_LIBRARIES -> additional libraries to link
    # ARG_UNPARSED_ARGUMENTS -> runtime args passed to add_test

    # add_executable(${target_name} ${source_file} ${ARG_SOURCES})
    add_executable(${target_name} ${source_file} ${ARG_SOURCES})

    target_link_libraries(${target_name} PRIVATE
            ${ARG_LIBRARIES}
            ${LIBCRYPTO}
            ${LIBRESOLV}
            ${LIBBSD}
            rt
            ${LIBPROC2}
            ${CMAKE_BINARY_DIR}/src/shared/libsusshi-shared.a
            ${CMAKE_BINARY_DIR}/external/lib/libssh.a
            ${CMAKE_BINARY_DIR}/external/lib/libcurl.a
            ${LIBIDN2}
            ${LIBPSL}
            ${LIBSSL}
            ${MICROHTTPD}
            ${LIBUTIL}
            ${LIBPCRE2}
            ${LIBPCAP}
            ${LIBEDIT}
            ${LIBTERMCAP}
            ${LIBJANSSON}
            ${LIBRESOLV}
            ${LIBSODIUM}
            ${LIBZ}
            ${CMAKE_BINARY_DIR}/external/lib/bstrlib.a
            ${CMAKE_BINARY_DIR}/external/lib/libunity.a
    )

    install(TARGETS ${target_name} DESTINATION tests)
    add_test(NAME ${folder_name}_${target_name} COMMAND ${target_name} ${ARG_UNPARSED_ARGUMENTS})
endfunction()

add_subdirectory(shared)
add_subdirectory(susshid)
