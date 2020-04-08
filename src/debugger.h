#include <windows.h>
#include <string>
#include <stdio.h>
#include <thread>
#include <iostream>
#include <mutex>
#include <queue>

class debugger
{
    private:
    	std::string fileName;
    	STARTUPINFO si;
    	PROCESS_INFORMATION pi;

    	bool debuggingActive = true;
    	bool debuggerActive = true;

    	std::mutex m_debuggingActive;
    	std::mutex m_debuggerActive;

        std::queue <std::string> commandQueue;

        HANDLE interThreadPipeRead;
        HANDLE interThreadPipeWrite;

    	DEBUG_EVENT debugEvent;
    	DWORD run (std::string);
    	DWORD processDebugEvents (DEBUG_EVENT * event, bool * debuggingActive);
    	DWORD processExceptions (DEBUG_EVENT * event);
    	void parseExecCommands ();
    	std::thread debuggerThread;
    	std::thread commandThread;
    	HANDLE commandEvent;
    	HANDLE continueDebugEvent;
    public:
		debugger (std::string);
		void interactive ();
};