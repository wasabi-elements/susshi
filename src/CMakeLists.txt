project(susshi-suite C)

include_directories(${CMAKE_SOURCE_DIR}/external/include)

add_subdirectory(shared)
add_subdirectory(susshid)
add_subdirectory(susshi-proxyd)
add_subdirectory(susshi-play)
add_subdirectory(susshi-last)
add_subdirectory(susshi-who)
add_subdirectory(susshi-decrypt)

