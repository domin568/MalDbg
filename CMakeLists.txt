cmake_minimum_required (VERSION 3.12)
set (PROJECT_NAME "MalDbg")
project (${PROJECT_NAME} VERSION 0.0.1)
set(CMAKE_BUILD_TYPE Release)
set (CMAKE_CXX_STANDARD 17)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})  # temporary 
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})  # temporary 
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})  # temporary

set ( M_CAPSTONE "capstone" )
set (CAPSTONE_DIR "${CMAKE_SOURCE_DIR}/${M_CAPSTONE}" CACHE PATH "Capstone main path")
set (CAPSTONE_INC "${CAPSTONE_DIR}/include" CACHE PATH "Capstone include path")

option(CAPSTONE_BUILD_STATIC_RUNTIME "Embed static runtime" OFF)
option(CAPSTONE_BUILD_STATIC "Build static library" OFF)
option(CAPSTONE_BUILD_SHARED "Build shared library" ON)
option(CAPSTONE_BUILD_DIET "Build diet library" OFF)
option(CAPSTONE_BUILD_TESTS "Build tests" OFF)
option(CAPSTONE_USE_DEFAULT_ALLOC "Use default memory allocation functions" ON)
option(CAPSTONE_BUILD_CSTOOL "Build cstool" OFF)

# set x86 architecture

option(CAPSTONE_ARM_SUPPORT "ARM support" OFF)
option(CAPSTONE_ARM64_SUPPORT "ARM64 support" OFF)
option(CAPSTONE_M680X_SUPPORT "M680X support" OFF)
option(CAPSTONE_M68K_SUPPORT "M68K support" OFF)
option(CAPSTONE_MIPS_SUPPORT "MIPS support" OFF)
option(CAPSTONE_MOS65XX_SUPPORT "MOS65XX support" OFF)
option(CAPSTONE_PPC_SUPPORT "PowerPC support" OFF)
option(CAPSTONE_SPARC_SUPPORT "Sparc support" OFF)
option(CAPSTONE_SYSZ_SUPPORT "SystemZ support" OFF)
option(CAPSTONE_XCORE_SUPPORT "XCore support" OFF)
option(CAPSTONE_X86_SUPPORT "x86 support" ON)
option(CAPSTONE_X86_REDUCE "x86 with reduce instruction sets to minimize library" OFF)
option(CAPSTONE_X86_ATT_DISABLE "Disable x86 AT&T syntax" ON)

option(CAPSTONE_TMS320C64X_SUPPORT "TMS320C64X support" OFF)
option(CAPSTONE_EVM_SUPPORT "EVM support" OFF)

set (CXX_COMPILER_FLAGS "-w -g")
set (CXX_LINKER_FLAGS "")

add_subdirectory (${CAPSTONE_DIR})
include_directories (${CAPSTONE_INC})
set (CAPSTONE_LIB $<TARGET_FILE:capstone-static> CACHE FILE CapstoneLib)

set (EXECUTABLE_NAME ${PROJECT_NAME})
set (SOURCE_FILES src/debugger.cpp src/main.cpp src/debugger.h src/breakpoint.h src/breakpoint.cpp src/memory.cpp src/memory.h src/utils.h src/utils.cpp)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_COMPILER_FLAGS}")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${CXX_LINKER_FLAGS}")

add_executable (${EXECUTABLE_NAME} ${SOURCE_FILES})

add_dependencies (${EXECUTABLE_NAME} capstone-shared)

target_link_libraries (${EXECUTABLE_NAME} shlwapi capstone-shared)

install( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )