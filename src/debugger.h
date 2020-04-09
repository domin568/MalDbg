#include <windows.h>
#include <string>
#include <stdio.h>
#include <thread>
#include <iostream>
#include <mutex>
#include <queue>
#include <regex>
#include <vector>
#include <map>
#include <capstone/capstone.h>

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
    UNKNOWN = 0xFF
};
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
struct command
{
    commandType type;
    std::vector <std::string> arguments;
};

// HELPER FUNCTIONS 

uint64_t parseStringToAddress (std::string);
int parseStringToNumber (std::string);

class debugger
{
    private:

        static constexpr int SHOW_CONTEXT_INSTRUCTION_COUNT = 10;

        DWORD run (std::string);
        DWORD processDebugEvents (DEBUG_EVENT * event, bool * debuggingActive);
        DWORD processExceptions (DEBUG_EVENT * event);
        void handleBreakpoint (EXCEPTION_DEBUG_INFO * exception);
        void breakpointEntryPoint (CREATE_PROCESS_DEBUG_INFO * info);
        void placeBreakpoint (uint64_t);
        void interactiveCommands ();
        void handleCommands (command *);
        void log (const char *, logType, ...);
        CONTEXT * getContext ();
        void setContext (CONTEXT *);
        void showContext ();
        void disasmAt (uint64_t, int);
        
        uint64_t debuggedProcessBaseAddress;

    	std::string fileName;
        std::string promptString = "maldbg> ";

    	STARTUPINFO si;
    	PROCESS_INFORMATION pi;

    	bool debuggingActive = true;
    	bool debuggerActive = true;
        bool interactiveMode = false;
        bool commandModeActive = false;

    	std::mutex m_debuggingActive;
    	std::mutex m_debuggerActive;

        std::map <uint64_t,uint8_t> breakpointsStolenBytes;
        std::vector <DWORD> interruptingEvents;

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
        void addSoftBreakpoint (uint64_t);
        void exitDebugger ();
        void continueExecution ();
};