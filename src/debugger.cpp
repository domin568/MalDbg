#include <shlwapi.h>
#include <strsafe.h>
#include "debugger.h"
#include <stdio.h>

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

void ErrorExit(LPTSTR lpszFunction) 
{ 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR)); 
    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK); 

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(dw); 
}

void breakpointEntryPoint (CREATE_PROCESS_DEBUG_INFO * info)
{

}
DWORD debugger::run ()
{
    while (debuggingActive)
    {
        if (!WaitForDebugEvent (&debugEvent,INFINITE))
        {
            ErrorExit(TEXT("WaitForDebugEvent"));
        }
        DWORD debugResponse = ProcessDebugEvent(&debugEvent, &debuggingActive);

        // Execute commands

        ContinueDebugEvent (debugEvent.dwProcessId,debugEvent.dwThreadId,debugResponse);
    }
    return 0;
}
debugger::debugger (const char * fileName)
{
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    ZeroMemory ( &debugEvent, sizeof(debugEvent));

    if (!CreateProcess (fileName,NULL,NULL,NULL,TRUE,DEBUG_PROCESS,NULL,NULL,&si,&pi))
    {
       ErrorExit(TEXT("CreateProces"));
    }
}
DWORD debugger::ProcessDebugEvent (DEBUG_EVENT * event, bool * debuggingActive) // returns dwContinueStatus 
{
    switch (event->dwDebugEventCode)
    {
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            char * modulePath = (char *) malloc (MAX_PATH + 1);
            CREATE_PROCESS_DEBUG_INFO * info = &event->u.CreateProcessInfo;
            GetFinalPathNameByHandleA () (info->hFile,modulePath,MAX_PATH+1,0);
            char * moduleName = PathFindFileNameA(modulePath + 4);
            printf ("[*] %s loaded, base address 0x%.08x\n entrypoint 0x%.08x\n",moduleName, info->lpBaseOfImage, info->lpStartAddress);
            free (modulePath);
            breakpointEntryPoint (info);
            return DBG_CONTINUE;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
        {
            EXIT_PROCESS_DEBUG_INFO * infoProc = &event->u.ExitProcess;
            printf ("[*] Process %u exited with code 0x%.08x\n",event->dwProcessId ,infoProc->dwExitCode);
            *debuggingActive = false;
            return DBG_CONTINUE;
        }
        case EXIT_THREAD_DEBUG_EVENT:
        {
            EXIT_THREAD_DEBUG_INFO * infoThread = &event->u.ExitThread;
            printf ("[*] Thread %u exited with code 0x%.08x\n",event->dwThreadId, infoThread->dwExitCode);
            return DBG_CONTINUE;
        }
        case CREATE_THREAD_DEBUG_EVENT:
        {
            CREATE_THREAD_DEBUG_INFO * infoThread = &event->u.CreateThread;
            printf ("[*] Thread 0x%x created with entry address 0x%.08x\n",event->dwThreadId, infoThread->lpStartAddress);
            return DBG_CONTINUE;
        }
        case LOAD_DLL_DEBUG_EVENT:
        {
            char * dllPath = (char *) malloc (MAX_PATH + 1);
            LOAD_DLL_DEBUG_INFO * loadInfo = &event->u.LoadDll;
            GetFinalPathNameByHandleA()(loadInfo->hFile,dllPath,MAX_PATH+1,0);
            char * dllName = PathFindFileNameA(dllPath + 4);
            printf ("[*] %s loaded (0x%.08x)\n",dllName,loadInfo->lpBaseOfDll);
            free (dllPath);
            return DBG_CONTINUE;
        }
        case UNLOAD_DLL_DEBUG_EVENT: // do not work with implicit loaded libraries ?
        {
            UNLOAD_DLL_DEBUG_INFO * unloadInfo = &event->u.UnloadDll;
            printf ("[*] 0x%.08x DLL unloaded\n",unloadInfo->lpBaseOfDll);
            return DBG_CONTINUE;
        }
        case EXCEPTION_DEBUG_EVENT:
        {
            EXCEPTION_DEBUG_INFO * exception = &event->u.Exception;
            if (exception->ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT && exception->ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP)
            {
                if (exception->dwFirstChance)
                {
                    printf ("[*] First chance exception: ");
                }
                else if (!exception->dwFirstChance)
                {
                    printf ("[*] Last chance exception: ");
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
                    printf ("[^] Breakpoint reached at 0x%.08x\n",exception->ExceptionRecord.ExceptionAddress);
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
                    printf ("[^] Single step\n");
                    return DBG_CONTINUE;
                }
                default:
                {
                    printf ("Exception not implemented yet ! \n");
                    return DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            break;
        }
        default:
        {
            printf ("[?] Not implemented Debug Event yet !\n");
            return DBG_EXCEPTION_NOT_HANDLED;
        }
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}