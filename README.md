# MalDbg

Writing debugger 4fun for Windows (x86-64). Debugger uses capstone framework to disassembly code.
Tested on Windows 7 (6.1.7601 SP1) with GCC 7.3.0 and CMake 3.14.7.

## How to compile
You'll need CMake and MinGW (tested) or MSVC (should work)

Compile on Windows with MinGW compiler

```
git clone --recurse-submodules https://github.com/domin568/MalDbg
mkdir build
cd build
cmake -G "MinGW Makefiles" ..
mingw32-make
```
This will produce bin/ folder containing MalDbg.exe and shared library libcapstone.dll.
## Usage

```
maldbg <exe>
```

## Commands

```
r, run 
```

Run debugged process (or restart while running).

```
b, bp, br, breakpoint <hexadecimal address>
```

Breakpoint at specified hexadecimal address. 0x is optional. 

```
context
```

Shows current state of execution (registers + disassembly for now).

```
disasm, disassembly <hexadecimal address> <instruction count>
```

Disassemblies specified number of instructions at specified address.

```
c, continue
```

Continue process.

```
e, exit
```

Exit from debugger. CTRL-C not yet interrupts debugged execution, just exiting.

## Features (for now)

1. Provide information about debugger events sent and exceptions raised. 
2. Interactive mode.
3. Prepared program structure for automating commands (like gdb script).
4. Ability to disassembly instructions at specified address.
5. Shows context of actual thread after each interrupt of execution.
4. Ability to manually set breakpoints.
5. Automatic breakpoint at entrypoint.
6. Colored output for cmd.exe.

## Visual presentation 

![](screen.png) 