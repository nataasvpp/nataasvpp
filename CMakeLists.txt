# Copyright (c) 2022 Cisco and/or its affiliates.

cmake_minimum_required(VERSION 3.9)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

#Required for VAPI header generation

project(vcdp)

if(NOT DEFINED CMAKE_INSTALL_LIBDIR AND EXISTS "/etc/debian_version")
  set(CMAKE_INSTALL_LIBDIR "lib/${CMAKE_LIBRARY_ARCHITECTURE}")
endif()
set(VPP_BINARY_DIR ${CMAKE_BINARY_DIR}/CMakeFiles)
set(VPP_LIBRARY_DIR ${CMAKE_INSTALL_LIBDIR} CACHE STRING "Relative library directory path")
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
find_package(VPP)

##############################################################################
# sanitizers
##############################################################################

option(VCDP_SANITIZE_ADDR "Enable Address Sanitizer" OFF)
set(VCDP_SANITIZE_ADDR_OPTIONS
  "unmap_shadow_on_exit=1:disable_coredump=0:abort_on_error=1:detect_leaks=0"
  CACHE
  STRING "Address sanitizer arguments"
)
add_compile_options(-Werror -Wall)

# Add this line to find the CBOR library
include(FetchContent)

# Find libcbor using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCBOR REQUIRED libcbor)

if (VCDP_SANITIZE_ADDR)
  add_compile_options(-fsanitize=address -fsanitize=undefined)
  add_compile_definitions(CLIB_SANITIZE_ADDR)
  set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=address ${CMAKE_EXE_LINKER_FLAGS}")
  set(CMAKE_SHARED_LINKER_FLAGS "-fsanitize=address ${CMAKE_SHARED_LINKER_FLAGS}")
endif (VCDP_SANITIZE_ADDR)

include(CTest)

add_subdirectory(plugins)

file(STRINGS "${VPP_INCLUDE_DIR}/vpp/app/version.h" VERSION_H_CONTENTS REGEX "#define VPP_BUILD_VER .+")
if (VERSION_H_CONTENTS)
  string(REGEX REPLACE "#define VPP_BUILD_VER " "" CPACK_PACKAGE_VERSION "${VERSION_H_CONTENTS}")
endif()
string(REPLACE "\"" "" CPACK_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
message(STATUS, "CPACK_PACKAGE_VERSION: ${CPACK_PACKAGE_VERSION}")

set(CPACK_PACKAGE_NAME "nataasvpp")
set(CPACK_PACKAGE_VENDOR "Cisco Systems Inc")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
	"NATaaS/VPP Plugin")
set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_CONTACT "otroan@employees.org")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Ole Troan")
include(CPack)
