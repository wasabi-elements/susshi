# define system dependent compiler flags

include(CheckCCompilerFlag)
include(CheckCCompilerFlagSSP)

if (UNIX AND NOT WIN32)
    #
    # Define GNUCC compiler flags
    #
    if (${CMAKE_C_COMPILER_ID} MATCHES "(GNU|Clang)")

        # add -Wconversion ?
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu23 -pedantic -pedantic-errors")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wmissing-prototypes -Wdeclaration-after-statement")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused -Wfloat-equal -Wpointer-arith -Wwrite-strings -Wformat-security")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-format-attribute -Wno-unused-parameter -Wno-unused-label")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-field-initializers -Wno-unused-command-line-argument")

        # with -fPIC
        check_c_compiler_flag("-fPIC" WITH_FPIC)
        if (WITH_FPIC)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
        endif (WITH_FPIC)

        check_c_compiler_flag_ssp("-fstack-protector-strong" WITH_STACK_PROTECTOR)
        if (WITH_STACK_PROTECTOR)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
        endif (WITH_STACK_PROTECTOR)

        check_c_compiler_flag_ssp("-fsanitize=safe-stack" WITH_SANITIZE_SAFE_STACK)
        if (WITH_SANITIZE_SAFE_STACK)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=safe-stack")
        endif (WITH_SANITIZE_SAFE_STACK)

        if (CMAKE_BUILD_TYPE)
            string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)

            if (CMAKE_BUILD_TYPE_LOWER MATCHES "(release|relwithdebinfo|minsizerel)")
                check_c_compiler_flag("-Wp,-D_FORTIFY_SOURCE=2" WITH_FORTIFY_SOURCE)
                if (WITH_FORTIFY_SOURCE)
                    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wp,-D_FORTIFY_SOURCE=2")
                endif (WITH_FORTIFY_SOURCE)
            endif ()

            if (CMAKE_BUILD_TYPE_LOWER MATCHES "(debug|relwithdebinfo)")
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWITH_FULL_DEBUG_OPTIONS=true -DWITH_PCAP")
                set(LIBSSH_PCAP ON)
                set(LIBSSH_CALLTRACE ON)
            else()
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -dead_strip -s")
                set(LIBSSH_PCAP OFF)
                set(LIBSSH_CALLTRACE OFF)
            endif ()

        endif ()
    endif (${CMAKE_C_COMPILER_ID} MATCHES "(GNU|Clang)")

    #
    # Check for large filesystem support
    #
    if (CMAKE_SIZEOF_VOID_P MATCHES "8")
        # with large file support
        execute_process(
            COMMAND
                getconf LFS64_CFLAGS
            OUTPUT_VARIABLE
                _lfs_CFLAGS
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    else (CMAKE_SIZEOF_VOID_P MATCHES "8")
        # with large file support
        execute_process(
            COMMAND
                getconf LFS_CFLAGS
            OUTPUT_VARIABLE
                _lfs_CFLAGS
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    endif (CMAKE_SIZEOF_VOID_P MATCHES "8")
    if (_lfs_CFLAGS)
        string(REGEX REPLACE "[\r\n]" " " "${_lfs_CFLAGS}" "${${_lfs_CFLAGS}}")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_lfs_CFLAGS}")
    endif (_lfs_CFLAGS)

endif (UNIX AND NOT WIN32)

