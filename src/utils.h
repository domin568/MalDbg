#pragma once

#include <windows.h>
#include <stdio.h>
#include <string>

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

void printfColor (const char *, DWORD, HANDLE, ... );
void log (const char *, logType, HANDLE,  ...);
void * parseStringToAddress (std::string);
int parseStringToNumber (std::string);