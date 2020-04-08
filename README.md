# MalDbg

Writing debugger 4fun for Windows (x86-64).
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

## Usage

```
maldbg <exe>
```

## Commands

```
r | run 
```

Run debugged process (or restart while running).

```
b | bp | br | breakpoint <hexadecimal address>
```

Breakpoint at specified hexadecimal address. 0x is optional. 

```
c | continue
```

Continue process.

```
e | exit
```

Exit from debugger. CTRL-C not yet interrupts debugged execution, just exiting.

## Features (for now)

1. Provide information about debugger events sent and exceptions raised. 
2. Interactive mode (continue, run, exit).
3. Manually setting breakpoints.
4. Breakpoint at entrypoint.
5. Prepared program structure for automating commands (like gdb script).
6. Colored output for cmd.exe.

## Visual presentation 

![](screen.png) 