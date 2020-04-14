#pragma once

#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <regex>

enum logType
{
    THREAD = 2,
    DLL = 3,
    WARNING = 5,
    PROMPT = 6,
    UNKNOWN_EVENT = 10,
    ERR = 12,
    INFO = 15,
    CONTEXT_REGISTERS = 31
};

enum class commandType
{
    RUN = 0,
    CONTINUE = 1,
    EXIT = 2,
    CONTEXT = 3,
    SOFT_BREAKPOINT = 4,
    HARD_BREAKPOINT = 5,
    MAP = 6,
    NEXT_INSTRUCTION = 7,
    STEP_IN = 8,
    DISASM = 9,
    TRACE_TO = 10,
    SHOW_BREAKPOINTS = 11,
    BREAKPOINT_DELETE = 12,
    SHOW_MEMORY_REGIONS = 13,
    HEXDUMP = 14,
    UNKNOWN = 0xFF
};

enum class argumentType
{
    ADDRESS = 0,
    NUMBER = 1
};
struct commandArgument
{
    argumentType type;
    std::string arg;
};
struct command
{
    commandType type;
    std::vector <commandArgument> arguments;
};

void printfColor (const char *, DWORD, HANDLE, ... );
void log (const char *, logType, HANDLE,  ...);
command * parseCommand (std::string);
void * parseStringToAddress (std::string);
int parseStringToNumber (std::string);