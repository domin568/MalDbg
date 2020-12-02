#pragma once

#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <stdio.h>
#include <thread>
#include <iostream>
#include <mutex>
#include <queue>
#include <set>
#include <vector>
#include <map>
#include <memory>
#include <ntstatus.h>
#include "breakpoint.h"
#include "memory.h"
#include "utils.h"
#include "peParser.h"
#include "symbolParse.h"
#include "structs.h"
#include "disassembly.h"

class debugger
{
    private:

        static constexpr int SHOW_CONTEXT_INSTRUCTION_COUNT = 10;

        void checkWOW64 ();
        DWORD run (std::string);
        DWORD processDebugEvents (DEBUG_EVENT *, bool *);
        DWORD processExceptions (DEBUG_EVENT*);
        DWORD processCreateProcess (DEBUG_EVENT *);
        void handleBreakpoint (EXCEPTION_DEBUG_INFO * exception, std::string, std::string);
        void handleSingleStep (EXCEPTION_DEBUG_INFO * exception, std::string, std::string);
        void breakpointEntryPoint (CREATE_PROCESS_DEBUG_INFO * info);
        void placeSoftwareBreakpoint (void *, bool, bool);
        void interactiveCommands ();
        void handleCommands (command *);
        CONTEXT getContext (DWORD);
        HANDLE getCurrentThread ();
        void setContext (CONTEXT &);
        void showContext ();
        void disasmAt (void *, int);
        void checkInterruptEvent ();
        breakpoint * searchForBreakpoint (std::vector<breakpoint> &, void * address);
        void * getNextInstructionAddress (void *);
        void showBreakpoints ();
        void showMemory ();
        bool deleteBreakpointByAddress (void *);
        bool deleteBreakpointByIndex (uint64_t);
        void setRegisterWithValue (std::string, uint64_t);

        bool parseSymbols (std::string);
        void parseFunctionNamesIAT ();
        std::string getFunctionNameForAddress (uint64_t address);
        void showBacktrace ();
        void showBacktrace64 ();
        void showBacktrace32 ();
        

        CONTEXT currentContext; // shared resource, never used in paralel
        memoryMap * currentMemoryMap;
        memoryHelper * memHelper;
        
        uint64_t debuggedProcessBaseAddress;
        int32_t wow64;
        bool is32bit;

    	std::string fileName;

    	STARTUPINFO si;
    	PROCESS_INFORMATION pi;

        exceptionData lastException;

    	bool debuggingActive = true;
    	bool debuggerActive = true;
        bool interactiveMode = false;
        bool commandModeActive = false;
        bool bypassInterruptOnce = false;
        bool coffSymbolsLoaded = true;
        bool systemBreakpoint = true;
        bool apilogSession = false;

    	std::mutex m_debuggingActive;
    	std::mutex m_debuggerActive;

        std::vector < std::map <uint64_t, std::string> > modulesExports;
        std::map <uint64_t, std::string> globalExportNames;
        std::vector <breakpoint> breakpoints;
        std::vector <memoryRegion> memoryRegions;
        std::vector <function> functionNames;
        std::set <DWORD> interruptingEvents;
        std::set <DWORD> interruptingExceptions;
        std::map <uint64_t, symbol> COFFsymbols;

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
