#pragma once

#include <windows.h>
#include <string>
#include <stdio.h>
#include <thread>
#include <iostream>
#include <mutex>
#include <queue>
#include <set>
#include <vector>
#include <capstone/capstone.h>

#include "breakpoint.h"
#include "memory.h"
#include "utils.h"

struct exceptionData
{
    DWORD exceptionType;
    DWORD rip;
    bool oneHitBreakpoint;
};

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
        void setRegisterWithValue (std::string, uint64_t);

        CONTEXT * currentContext; // shared resource, never used in paralel
        memoryMap * currentMemoryMap;
        memoryHelper * memHelper;
        
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
