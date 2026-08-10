project(susshi-docs)

# if (WITH_LIBSSH)
#    set(LIBSSH_SOURCE
#      "${CMAKE_SOURCE_DIR}/susshi/build/external/.libssh/src/libssh/doc ${CMAKE_SOURCE_DIR}/susshi/build/external/.libssh/src/libssh/src ${CMAKE_SOURCE_DIR}/susshi/build/external/.libssh/src/libssh/include/libssh"
#    )
# endif ()

if(${CMAKE_VERSION} VERSION_GREATER "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

include(FetchContent)

FetchContent_Declare(
    doxygen-awesome-css
    URL https://github.com/jothepro/doxygen-awesome-css/archive/refs/heads/main.zip
    DOWNLOAD_EXTRACT_TIMESTAMP
)

FetchContent_MakeAvailable(doxygen-awesome-css)

# Save the location the files were cloned into
# This allows us to get the path to doxygen-awesome.css
FetchContent_GetProperties(doxygen-awesome-css SOURCE_DIR AWESOME_CSS_DIR)

# Generate the Doxyfile
set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
set(DOXYFILE_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
configure_file(${DOXYFILE_IN} ${DOXYFILE_OUT} @ONLY)

include(Doxygen)
enable_doxygen()

# Subdirectories
add_subdirectory(static)
