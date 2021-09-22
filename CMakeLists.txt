cmake_minimum_required(VERSION 3.9)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

#Required for VAPI header generation
set(VPP_BINARY_DIR ${CMAKE_BINARY_DIR}/CMakeFiles)

project(vcdp)
find_package(VPP)
add_subdirectory(plugins)
