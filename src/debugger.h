#pragma once

#include <windows.h>
#include <string>
#include <stdio.h>
#include <thread>
#include <iostream>
#include <mutex>
#include <queue>
#include <regex>
#include <set>
#include <vector>
#include <capstone/capstone.h>

#include "breakpoint.h"
#include "memory.h"
#include "utils.h"

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
struct exceptionData
{
    DWORD exceptionType;
    DWORD rip;
    bool oneHitBreakpoint;
};

// HELPER FUNCTIONS 

class debugger
{
    private:

        static constexpr int SHOW_CONTEXT_INSTRUCTION_COUNT = 10;

        DWORD run (std::string);
        DWORD processDebugEvents (DEBUG_EVENT * event, bool * debuggingActive);
        DWORD processExceptions (DEBUG_EVENT * event);
        void handleBreakpoint (EXCEPTION_DEBUG_INFO * exception);
        void handleSingleStep (EXCEPTION_DEBUG_INFO * exception);
        void breakpointEntryPoint (CREATE_PROCESS_DEBUG_INFO * info);
        void placeSoftwareBreakpoint (void *, bool);
        void interactiveCommands ();
        void handleCommands (command *);
        CONTEXT * getContext ();
        void setContext (CONTEXT *);
        void showContext ();
        void disasmAt (void *, int);
        void checkInterruptEvent ();
        breakpoint * searchForBreakpoint (void * address);
        void * getNextInstructionAddress (void *);
        void showBreakpoints ();
        void showMemory ();
        bool deleteBreakpointByAddress (void *);
        bool deleteBreakpointByIndex (uint64_t);

        CONTEXT * currentContext; // shared resource, never used in paralel
        memoryMap * currentMemoryMap;
        
        uint64_t debuggedProcessBaseAddress;

    	std::string fileName;


    	STARTUPINFO si;
    	PROCESS_INFORMATION pi;

        exceptionData lastException;

    	bool debuggingActive = true;
    	bool debuggerActive = true;
        bool interactiveMode = false;
        bool commandModeActive = false;
        bool bypassInterruptOnce = false;

    	std::mutex m_debuggingActive;
    	std::mutex m_debuggerActive;

        //std::map <uint64_t,uint8_t> breakpointsStolenBytes;
        std::vector <breakpoint> breakpoints;
        std::vector <memoryRegion> memoryRegions;
        std::set <DWORD> interruptingEvents;
        std::set <DWORD> interruptingExceptions;

    	DEBUG_EVENT currentDebugEvent;

    	std::thread debuggerThread;
    	std::thread commandThread;

    	HANDLE commandEvent;
    	HANDLE continueDebugEvent;
        HANDLE stdoutHandle;
        HANDLE debuggedProcessHandle;

    public:

		debugger (std::string);
		void interactive ();
        void addSoftBreakpoint (void *);
        void exitDebugger ();
        void continueExecution ();
};
