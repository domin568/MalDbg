#include <shlwapi.h>
#include <strsafe.h>
#include "debugger.h"


typedef DWORD (*t_GetFinalPathNameByHandleA) (HANDLE hFile,LPSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);

t_GetFinalPathNameByHandleA GetFinalPathNameByHandleA()
{
    static t_GetFinalPathNameByHandleA f_GetFinalPathNameByHandleA = NULL;
    if (!f_GetFinalPathNameByHandleA)
    {
        HMODULE h_kernel32Dll = GetModuleHandle("kernel32.dll"); // kernel32 is loaded into EVERY process!
        f_GetFinalPathNameByHandleA = (t_GetFinalPathNameByHandleA) GetProcAddress(h_kernel32Dll, "GetFinalPathNameByHandleA");
    }
    return f_GetFinalPathNameByHandleA;
}

uint64_t parseStringToAddress (std::string toConvert)
{
    uint64_t address;
    sscanf (toConvert.c_str(),"%x",&address);
    return address;
}

void debugger::breakpointEntryPoint (CREATE_PROCESS_DEBUG_INFO * info)
{
    uint64_t entryRVA = (uint64_t) info->lpStartAddress - (uint64_t) info->lpBaseOfImage;
    uint64_t entryVA = (uint64_t) info->lpBaseOfImage + (uint64_t) entryRVA;
    placeBreakpoint (entryVA);
}
DWORD debugger::run (std::string fileName)
{
    ResetEvent (commandEvent);
    ResetEvent (continueDebugEvent);

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    ZeroMemory ( &debugEvent, sizeof(debugEvent));

    if (!CreateProcess (fileName.c_str(),NULL,NULL,NULL,TRUE,DEBUG_PROCESS,NULL,NULL,&si,&pi))
    {
       log ("Cannot start debugged process\n",logType::ERR);
       return 1;
    }
    debuggedProcessHandle = pi.hProcess;
    while (debuggingActive)
    {
        if (!WaitForDebugEvent (&debugEvent,INFINITE))
        {
            log ("WaitForDebugEven returned nonzero value\n",logType::ERR);
            return 2;
        }
        DWORD debugResponse = processDebugEvents(&debugEvent, &debuggingActive);

        if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            SetEvent (commandEvent);
            WaitForSingleObject (continueDebugEvent,INFINITE);
            // wait for command to be executed
        }
        
        ContinueDebugEvent (debugEvent.dwProcessId,debugEvent.dwThreadId,debugResponse);
    }
    return 0;
}
command * parseCommand (std::string c)
{
    command * comm = new command ();

    std::regex continueRegex ("^(c|cont|continue)\\s*$");
    std::regex runRegex ("^(r|run)\\s*$");
    std::regex exitRegex ("^(e|exit)\\s*$");
    std::regex softBreakpointRegex ("^(b|br|bp|breakpoint){1}\\s+(0x)?([0-9a-fA-F]+)$");
    //std::regex softBreakpointRegex ("(b|br|bp|breakpoint)\\s+(0x)?[0-9a-fA-F]+");
    std::regex hardBreakpointRegex ("(hb|hardware breakpoint)\\s+(0x?[0-9a-fA-F]+)");

    std::smatch continueMatches;
    std::smatch runMatches;
    std::smatch exitMatches;
    std::smatch softBreakpointMatches;
    std::smatch hardBreakpointMatches;


    if (std::regex_search (c, continueMatches, continueRegex))
    {
        comm->type = commandType::CONTINUE;
        return comm;
    }
    else if (std::regex_search (c, runMatches, runRegex))
    {
        comm->type = commandType::RUN;
        return comm;   
    }
    else if (std::regex_search (c, exitMatches, exitRegex))
    {
        comm->type = commandType::EXIT;
        return comm;   
    }
    else if (std::regex_match (c, softBreakpointMatches, softBreakpointRegex))
    {
        comm->type = commandType::SOFT_BREAKPOINT;
        comm->arguments.push_back (softBreakpointMatches[3].str());
        return comm;
    }

    comm->type = commandType::UNKNOWN;
    return comm;
}
void debugger::handleCommands(command * currentCommand)
{
    if (currentCommand->type == commandType::CONTINUE)
    {
        SetEvent (continueDebugEvent);
        commandModeActive = false;
    }
    else if (currentCommand->type == commandType::SOFT_BREAKPOINT)
    {
        uint64_t breakpointAddress = parseStringToAddress(currentCommand->arguments[0]);
        placeBreakpoint (breakpointAddress);
    }
    else if (currentCommand->type == commandType::RUN)
    {
        if (debuggingActive)
        {
            log ("The program is being debugged, running it again\n",logType::WARNING);
        }
        SetEvent (continueDebugEvent);
        debuggingActive = false;
        debuggerThread.join();
        debuggingActive = true;
        debuggerThread = std::thread(debugger::run, this, fileName);
        commandModeActive = false;
    }
    else if (currentCommand->type == commandType::EXIT)
    {
        std::lock_guard<std::mutex> l_debuggingActive (m_debuggingActive);
        debuggerActive = false;
        debuggingActive = false;
        SetEvent (continueDebugEvent);
        debuggerThread.join();
        commandModeActive = false;
    }
    
}
void debugger::interactiveCommands ()
{
    std::string c;
    while (debuggerActive)
    {
        WaitForSingleObject (commandEvent,INFINITE);
        commandModeActive = true;
        while (commandModeActive)
        {
            log ("",logType::PROMPT);
            std::getline(std::cin, c);
            command * currentCommand = parseCommand (c);

            if (currentCommand->type == commandType::UNKNOWN)
            {
                log ("Unknown command provided\n",logType::ERR);
            }
            else
            {
                handleCommands (currentCommand);
            }
            delete currentCommand;
        }
    }
}
void debugger::interactive ()
{
    if (!interactiveMode)
    {
        interactiveMode = true;
        commandThread = std::thread (debugger::interactiveCommands, this);
        commandThread.join ();
    }
    interactiveMode = false;
}
void debugger::log (const char * messageFormatted, logType type, ...)
{   
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD savedAttributes;
    GetConsoleScreenBufferInfo(stdoutHandle, &consoleInfo);
    savedAttributes = consoleInfo.wAttributes;

    SetConsoleTextAttribute(stdoutHandle, type);
    switch (type)
    {
        case logType::THREAD:
        {
            printf ("[+] ");
            break;
        }
        case logType::DLL:
        {
            printf ("[+] ");
            break;
        }
        case logType::WARNING:
        {
            printf ("[!] ");
            break;
        }
        case logType::PROMPT:
        {
            printf ("%s",promptString.c_str());
            SetConsoleTextAttribute(stdoutHandle, savedAttributes);
            return;
        }
        case logType::INFO:
        {
            printf ("[*] ");
            break;
        }
        case logType::ERR:
        {
            printf ("[!] ");
            break;
        }
        case logType::UNKNOWN_EVENT:
        {
            printf ("[?] ");
            break;
        }
    }    
    SetConsoleTextAttribute(stdoutHandle, savedAttributes);
    va_list args;
    va_start(args, type);
    vprintf (messageFormatted,args); // vprintf when we do not know how many arguments we gonna pass
    va_end (args);
}
void debugger::placeBreakpoint (uint64_t address)
{
    uint8_t byte;
    uint8_t int3Byte = 0xcc;
    if (!ReadProcessMemory (debuggedProcessHandle, (LPCVOID) address, &byte, 1, NULL))
    {
        log ("Cannot get byte at address %.08x\n",logType::ERR,address);
    }
    if (!WriteProcessMemory (debuggedProcessHandle, (LPVOID) address, &int3Byte, 1, NULL))
    {
        log ("Cannot write int3 byte at address %.08x\n",logType::ERR,address);
    }
    breakpointsStolenBytes [address] = byte;
}
void debugger::addSoftBreakpoint (uint64_t address)
{
    if (!interactiveMode)
    {
        WaitForSingleObject (commandEvent,INFINITE);
        placeBreakpoint (address);
    }
}
void debugger::continueExecution ()
{
    if (!interactiveMode)
    {
        WaitForSingleObject (commandEvent,INFINITE);
        SetEvent (continueDebugEvent);
    }
}
void debugger::exitDebugger ()
{
    if (!interactiveMode)
    {
        debuggerActive = false;
        debuggingActive = false;
        SetEvent (continueDebugEvent);
        debuggerThread.join();
    }   
}
debugger::debugger (std::string fileName)
{
    stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    commandEvent = CreateEventA (NULL,false,false,"commandEvent");
    continueDebugEvent = CreateEventA (NULL,false,false,"continueDebugEvent");
    this->fileName = fileName;
    debuggerThread = std::thread(debugger::run, this, fileName);
}
DWORD debugger::processExceptions (DEBUG_EVENT * event)
{
    EXCEPTION_DEBUG_INFO * exception = &event->u.Exception;
    if (exception->ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT && exception->ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP)
    {
        if (exception->dwFirstChance)
        {
            log ("First chance exception: ", logType::ERR);
        }
        else if (!exception->dwFirstChance)
        {
            log ("Last chance exception: ", logType::ERR);
        }   
    }
    switch (exception->ExceptionRecord.ExceptionCode)
    {
        case EXCEPTION_ACCESS_VIOLATION:
        {
            printf ("Access Violation (0x%.08x) at address 0x%.08x\n",exception->ExceptionRecord.ExceptionCode, exception->ExceptionRecord.ExceptionAddress);
            return DBG_EXCEPTION_NOT_HANDLED;
        }
        case EXCEPTION_BREAKPOINT:
        {
            uint64_t breakpointAddress = (uint64_t) exception->ExceptionRecord.ExceptionAddress;
            if (breakpointsStolenBytes.count(breakpointAddress) > 0)
            {
                uint8_t stolenByte = breakpointsStolenBytes[breakpointAddress];
                log ("User breakpoint reached at 0x%.08x\n",logType::INFO,breakpointAddress);
                if (!WriteProcessMemory (debuggedProcessHandle, (LPVOID) breakpointAddress, &stolenByte ,1, NULL)) // restore stolen byte
                {
                    log ("Cannot restore stolen byte\n",logType::ERR);
                } 
            }
            else
            {
                log ("System breakpoint reached at 0x%.08x\n", logType::INFO, breakpointAddress);
            }
            return DBG_CONTINUE;
        }
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        {
            printf ("Division by zero exception at 0x%.08x\n",exception->ExceptionRecord.ExceptionAddress);
            return DBG_EXCEPTION_NOT_HANDLED;
        }
        case EXCEPTION_PRIV_INSTRUCTION:
        {
            printf ("Privileged instruction was spotted at 0x%.08x\n",exception->ExceptionRecord.ExceptionAddress);  
            return DBG_EXCEPTION_NOT_HANDLED;
        }
        case EXCEPTION_SINGLE_STEP:
        {
            log ("Single step \n", logType::INFO);
            return DBG_CONTINUE;
        }
        default:
        {
            log ("Not implemented exception yet\n", logType::UNKNOWN_EVENT);
            return DBG_EXCEPTION_NOT_HANDLED;
        }
    }
}
DWORD debugger::processDebugEvents (DEBUG_EVENT * event, bool * debuggingActive) // returns dwContinueStatus 
{
    switch (event->dwDebugEventCode)
    {
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            char * modulePath = (char *) malloc (MAX_PATH + 1);
            CREATE_PROCESS_DEBUG_INFO * info = &event->u.CreateProcessInfo;
            GetFinalPathNameByHandleA () (info->hFile,modulePath,MAX_PATH+1,0);
            char * moduleName = PathFindFileNameA(modulePath + 4);
            log ("%s loaded, base address 0x%.08x entrypoint 0x%.08x\n",logType::INFO,moduleName, info->lpBaseOfImage, info->lpStartAddress);
            debuggedProcessBaseAddress = (uint64_t) info->lpBaseOfImage;
            free (modulePath);
            breakpointEntryPoint (info);
            return DBG_CONTINUE;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
        {
            std::lock_guard<std::mutex> l_debuggingActive (m_debuggingActive);

            EXIT_PROCESS_DEBUG_INFO * infoProc = &event->u.ExitProcess;
            log ("Process %u exited with code 0x%.08x\n", logType::INFO, event->dwProcessId ,infoProc->dwExitCode);
            SetEvent (commandEvent);
            *debuggingActive = false;
            return DBG_CONTINUE;
        }
        case EXIT_THREAD_DEBUG_EVENT:
        {
            EXIT_THREAD_DEBUG_INFO * infoThread = &event->u.ExitThread;
            log ("Thread %u exited with code 0x%.08x\n", logType::THREAD, event->dwThreadId, infoThread->dwExitCode);
            return DBG_CONTINUE;
        }
        case CREATE_THREAD_DEBUG_EVENT:
        {
            CREATE_THREAD_DEBUG_INFO * infoThread = &event->u.CreateThread;
            log ("Thread 0x%x created with entry address 0x%.08x\n", logType::THREAD, event->dwThreadId, infoThread->lpStartAddress);
            return DBG_CONTINUE;
        }
        case LOAD_DLL_DEBUG_EVENT:
        {
            char * dllPath = (char *) malloc (MAX_PATH + 1);
            LOAD_DLL_DEBUG_INFO * loadInfo = &event->u.LoadDll;
            GetFinalPathNameByHandleA()(loadInfo->hFile,dllPath,MAX_PATH+1,0);
            char * dllName = PathFindFileNameA(dllPath + 4);
            log ("%s loaded (0x%.08x)\n",logType::DLL,dllName,loadInfo->lpBaseOfDll);
            free (dllPath);
            return DBG_CONTINUE;
        }
        case UNLOAD_DLL_DEBUG_EVENT: // do not work with implicit loaded libraries ?
        {
            UNLOAD_DLL_DEBUG_INFO * unloadInfo = &event->u.UnloadDll;
            log ("0x%.08x DLL unloaded\n",logType::DLL,unloadInfo->lpBaseOfDll);
            return DBG_CONTINUE;
        }
        case EXCEPTION_DEBUG_EVENT:
        {
            return processExceptions (event);
            break;
        }
        default:
        {
            log ("Not implemented debug event yet \n", logType::UNKNOWN_EVENT);
            return DBG_EXCEPTION_NOT_HANDLED;
        }
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}