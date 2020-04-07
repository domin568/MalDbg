# MalDbg

Writing debugger 4fun for Windows.
Tested on Windows 7 (6.1.7601 SP1) with GCC 7.3.0 and CMake 3.14.7.

## How to compile
You'll need CMake and MinGW (tested) or MSVC (should work)

Compile on Windows with MinGW compiler

```
mkdir build
cd build
cmake -G "MinGW Makefiles" ..
mingw32-make
```

## Functionality (for now)

1. Provide information about debugger events and exceptions. 
2. To be continued..
