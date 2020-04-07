#include <windows.h>

class debugger
{
    private:
    	STARTUPINFO si;
    	PROCESS_INFORMATION pi;
    	bool debuggingActive = true;
    	DEBUG_EVENT debugEvent;

    public:
		debugger (const char *);
		DWORD run ();  
		DWORD ProcessDebugEvent (DEBUG_EVENT * event, bool * debuggingActive);
};