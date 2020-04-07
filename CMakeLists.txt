cmake_minimum_required (VERSION 3.12)
set (PROJECT_NAME "MalDbg")
project (${PROJECT_NAME} VERSION 0.0.1)
set(CMAKE_BUILD_TYPE Release)

set (CMAKE_CXX_STANDARD 14)

set (EXECUTABLE_NAME ${PROJECT_NAME})
set (SOURCE_FILES src/debugger.cpp src/main.cpp src/debugger.h)

set (CXX_COMPILER_FLAGS "-Wall -g")
set (CXX_LINKER_FLAGS "")

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_COMPILER_FLAGS}")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${CXX_LINKER_FLAGS}")

add_executable (${EXECUTABLE_NAME}  ${SOURCE_FILES})
target_link_libraries (${EXECUTABLE_NAME} shlwapi)