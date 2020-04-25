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
help
```

Show help information.

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

```
si, step in, s i
```
Step one instruction into.

```
ni, next instruction, n i
```

Step one instruction further in current frame

```
bl, show breakpoints, breakpoint list, b l, b list, breakpoint l
```

Show active breakpoints, their type and hit count.

```
bd, b delete, breakpoint delete <index/address>
```

Delete breakpoint by index (providing decimal number) or by address (providing hexadecimal address).

``` 
vmmap, memory mappings, map
```

Show map of whole virtual memory for this process including modules and their sections names.

```
hexdump, h, hex <address> <size>
```

Print 8 byte width hexdump with ASCII at specified address of given size. 

```
sr, set register <register> <hex value>
```

Sets register (rax, rcx, rflags...) with desired value.

```
write memory, wm <hex address> <size decimal> <hex value>
```

Write integer value at specified address up to 8 bytes.

## Features (for now)

1. Provide information about debugger events sent and exceptions raised. 
2. Interactive mode.
3. Prepared program structure for automating commands (like gdb script).
4. Ability to disassembly instructions at specified address.
5. Shows context of actual thread after each interrupt of execution.
6. Ability to manually set breakpoints (one hit also).
7. Automatic breakpoint at entrypoint.
8. Colored output for cmd.exe.
9. Next instruction and step in commands.
10. Show actual breakpoints with their hit count.
11. Delete breakpoints by index or by address.
12. Showing map of virtual memory for current process.
13. vmmap shows also names of modules and their sections.
14. Setting registers with desired values.
15. Printiing hexdump of memory.
16. Writing integer values to memory (up to 8 bytes)

## Visual presentation 

![](screen.png) 

## TODO 
- callstack.
- vmmap with names (need to parse PE files). &#x2611;