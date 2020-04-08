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

enum class commandType
{
    RUN = 0,
    CONTINUE = 1,
    EXIT = 2,
    SOFT_BREAKPOINT = 3,
    HARD_BREAKPOINT = 4,
    MAP = 5,
    NEXT_INSTRUCTION = 6,
    STEP_IN = 7,
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
};
struct command
{
    commandType type;
    std::vector <std::string> arguments;
};

// HELPER FUNCTIONS 

uint64_t parseStringToAddress (std::string);

class debugger
{
    private:

        DWORD run (std::string);
        DWORD processDebugEvents (DEBUG_EVENT * event, bool * debuggingActive);
        DWORD processExceptions (DEBUG_EVENT * event);
        void breakpointEntryPoint (CREATE_PROCESS_DEBUG_INFO * info);
        void placeBreakpoint (uint64_t);
        void interactiveCommands ();
        void handleCommands (command *);
        void log (const char *, logType, ...);
        
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

    	DEBUG_EVENT debugEvent;

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