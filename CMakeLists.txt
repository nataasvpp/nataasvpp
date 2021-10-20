cmake_minimum_required(VERSION 3.9)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

#Required for VAPI header generation
set(VPP_BINARY_DIR ${CMAKE_BINARY_DIR}/CMakeFiles)

project(vcdp)
find_package(VPP)

##############################################################################
# sanitizers
##############################################################################

option(VPP_ENABLE_SANITIZE_ADDR "Enable Address Sanitizer" OFF)
set(VPP_SANITIZE_ADDR_OPTIONS
  "unmap_shadow_on_exit=1:disable_coredump=0:abort_on_error=1:detect_leaks=0"
  CACHE
  STRING "Address sanitizer arguments"
)

if (VPP_ENABLE_SANITIZE_ADDR)
  add_compile_options(-fsanitize=address)
  add_compile_definitions(CLIB_SANITIZE_ADDR)
  set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=address ${CMAKE_EXE_LINKER_FLAGS}")
  set(CMAKE_SHARED_LINKER_FLAGS "-fsanitize=address ${CMAKE_SHARED_LINKER_FLAGS}")
endif (VPP_ENABLE_SANITIZE_ADDR)

add_subdirectory(plugins)
