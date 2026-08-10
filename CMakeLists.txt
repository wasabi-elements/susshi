# Required cmake version
cmake_minimum_required(VERSION 3.23)

project(susshi C)

# Global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/cmake/Modules
)

# add definitions
include(SusshiVersion)
include(DefineCMakeDefaults)
include(DefinePlatformDefaults)
include(DefineCompilerFlags)
include(DefineInstallationPaths)
include(CheckLibraryExists)

# Add CTest for running the tests.
include(CTest)

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please navigate to build directory ./build and run 'cmake .. [options]' there.")

# Check for functions
set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h bsd/unistd.h)

check_library_exists(bsd setproctitle_init "" HAVE_SETPROCTITLE_INIT)
if(HAVE_SETPROCTITLE_INIT)
    add_definitions("-DHAVE_SETPROCTITLE_INIT")
endif()

check_library_exists(bsd setproctitle "" HAVE_SETPROCTITLE)
if(HAVE_SETPROCTITLE)
    add_definitions("-DHAVE_SETPROCTITLE")
endif()

set(SUSSHI_INCLUDE_DIRS
  ${CMAKE_SOURCE_DIR}/include
  CACHE INTERNAL "susshi include directories"
)

set(SUSSHI_BUILD_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_BINARY_DIR}/external/include
)

include_directories(
  ${SUSSHI_INCLUDE_DIRS}
  ${SUSSHI_BUILD_INCLUDE_DIRS}
)

# Subdirectories
add_subdirectory(external)
add_subdirectory(include)
add_subdirectory(src)

# Docs
if(DEFINED ENV{INCLUDE_DOXY_DOCS})
    add_subdirectory(docs)
endif()

# Comment out if you don't want to add tests
add_subdirectory(tests)

enable_testing()

# Installation target
if (NOT CMAKE_INSTALL_PREFIX)
    set(CMAKE_INSTALL_PREFIX "/opt/wasabi/susshi")
endif()

# License texts, laid out like the copyright files of distribution packages: share/doc/<component>/.
# The external components are collected into ${CMAKE_BINARY_DIR}/LICENSES by external/CMakeLists.txt.
# Unity is a test-only dependency and is not shipped.
install(FILES LICENSE.md THIRD-PARTY-NOTICES.md DESTINATION share/doc)
install(DIRECTORY ${CMAKE_BINARY_DIR}/LICENSES/ DESTINATION share/doc
        PATTERN "unity" EXCLUDE)