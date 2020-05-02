#include <shlwapi.h>
#include <strsafe.h>
#include "debugger.h"

typedef DWORD (*t_GetFinalPathNameByHandleA) (HANDLE, LPSTR, DWORD, DWORD);

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

breakpoint * debugger::searchForBreakpoint (std::vector <breakpoint> & b, void * address)
{
    for (auto & i : b)
    {
        if (i.getAddress() == address)
        {
            return &i;
        }
    }
    return nullptr;
}
void * debugger::getNextInstructionAddress (void * ref)
{
    uint8_t * codeBuffer = new uint8_t [50];
    if (!ReadProcessMemory (debuggedProcessHandle, (LPCVOID) ref, codeBuffer, 50 , NULL))
    {
        log ("Cannot read memory at %.16llx\n",logType::ERR, stdoutHandle,  ref);
        delete codeBuffer;
        return nullptr;
    }
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        delete codeBuffer;
        return nullptr;
    }
    count = cs_disasm (handle, codeBuffer, 50 , (uint64_t) ref, 0, &insn);
    if (count >= 2)
    {  
        void * toRet = (void *) insn[1].address;
        cs_free (insn,count);
        delete codeBuffer;
        return toRet;
    }
    else
    {
        delete codeBuffer;
        return nullptr;
    }
    
}
void debugger::disasmAt (void * address, int numberOfInstructions)
{
    static disassembler d {debuggedProcessBaseAddress, &COFFsymbols, &functionNames};
    std::vector <breakpoint *> disassembledBreakpoints;
    uint8_t * codeBuffer = new uint8_t [numberOfInstructions * d.MAX_INSTRUCTION_LENGTH];
    uint64_t readBytes;
    if (!ReadProcessMemory (debuggedProcessHandle, (LPCVOID) address, codeBuffer, numberOfInstructions * d.MAX_INSTRUCTION_LENGTH , &readBytes) && readBytes == 0)
    {
        log ("Cannot read memory at %.16llx\n",logType::ERR, stdoutHandle, address);
        return;
    }
    if (readBytes != numberOfInstructions * d.MAX_INSTRUCTION_LENGTH)
    {
        log ("Could read only %i bytes of memory at %.16llx\n",logType::ERR, stdoutHandle,readBytes , address);
    }
    /*
    memoryHelper h (debuggedProcessHandle, stdoutHandle);
    h.printHexdump (address, readBytes);
    */
    d.disasm ((uint64_t) address, codeBuffer, readBytes, numberOfInstructions, breakpoints);    
    delete codeBuffer;
}
CONTEXT debugger::getContext (DWORD flags)
{
    CONTEXT lcContext;
    lcContext.ContextFlags = flags;
    HANDLE threadHandle = OpenThread (THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, currentDebugEvent.dwThreadId);
    if (threadHandle == NULL)
    {
        log ("Cannot get thread handle when getting context \n",logType::ERR, stdoutHandle);
        return lcContext;
    }
    if(SuspendThread(threadHandle) == -1)
    {
        log ("Cannot get handle to thread that caused exception  \n",logType::ERR, stdoutHandle);
        return lcContext;
    }

    if (!GetThreadContext(threadHandle, &lcContext))
    {
        log ("Cannot get thread context that caused exception \n",logType::ERR, stdoutHandle);
        return lcContext;
    }
    if(ResumeThread(threadHandle) == -1)
    {
        log ("Cannot resume thread after getting context \n",logType::ERR, stdoutHandle);
        return lcContext;
    }
    return lcContext;
}
void debugger::setContext (CONTEXT & context)
{
    HANDLE threadHandle = OpenThread (THREAD_SET_CONTEXT, FALSE, currentDebugEvent.dwThreadId);
    if (!SetThreadContext(threadHandle, &context))
    {
        log ("Cannot set thread context",logType::ERR, stdoutHandle);
        return;
    }
}
void debugger::showContext ()
{
    CONTEXT lcContext = this->currentContext;

    printf ("lcContext->RIP = %.16llx \n", lcContext.Rip);

    printf ("\n");

    DWORD flg = lcContext.EFlags;

    log ("RAX %.16llx RBX %.16llx RCX %.16llx\nRDX %.16llx RSI %.16llx RDI %.16llx",logType::CONTEXT_REGISTERS, stdoutHandle, 
        lcContext.Rax, lcContext.Rbx, lcContext.Rcx, lcContext.Rdx, lcContext.Rsi, lcContext.Rdi);
    log ("R8  %.16llx R9  %.16llx R10 %.16llx\nR11 %.16llx R12 %.16llx R13 %.16llx\nR14 %.16llx R15 %.16llx FLG %.16llx",logType::CONTEXT_REGISTERS, stdoutHandle, 
        lcContext.R8, lcContext.R9, lcContext.R10, lcContext.R11, lcContext.R12, lcContext.R13, lcContext.R14, lcContext.R15, lcContext.EFlags);
    log ("RIP %.16llx RBP %.016x RSP %.016x", logType::CONTEXT_REGISTERS, stdoutHandle, lcContext.Rip, lcContext.Rbp, lcContext.Rsp);

    log ("ZF %.1x CF %.1x PF %.1x AF %.1x SF %.1x TF %.1x IF %.1x DF %.1x OF %.1x",logType::CONTEXT_REGISTERS, stdoutHandle, 
        (flg & (1 << 6)) >> 6, flg & 1, (flg & (1 << 2)) >> 2, (flg & (1 << 4)) >> 4, (flg & (1 << 7)) >> 7, (flg & (1 << 8)) >> 8,
        (flg & (1 << 9)) >> 9, (flg & (1 << 10)) >> 10, (flg & (1 << 11)) >> 11 );

    printf ("\n");

    uint64_t displacement;
    SymInitialize(debuggedProcessHandle, NULL, TRUE ); // ?????? 
    char * buffer = new char [sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    memset (buffer, 0, sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR));
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO) buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    SymFromAddr(debuggedProcessHandle, ( ULONG64 )currentContext.Rip, &displacement, pSymbol);
    size_t symbolNameSize = strlen (pSymbol->Name);

    std::string internalFuncName = getFunctionNameForAddress((uint64_t)currentContext.Rip);
    log ("-----> %s\n",
        logType::INFO,
        stdoutHandle,
        (symbolNameSize > 0 ? pSymbol->Name : internalFuncName.c_str())
        );

    delete [] buffer;

    printf ("\n");

    disasmAt ((void *)lcContext.Rip, SHOW_CONTEXT_INSTRUCTION_COUNT);   

    printf ("\n"); 
}

void debugger::breakpointEntryPoint (CREATE_PROCESS_DEBUG_INFO * info)
{
    uint64_t entryRVA = (uint64_t) info->lpStartAddress - (uint64_t) info->lpBaseOfImage;
    uint64_t entryVA = (uint64_t) info->lpBaseOfImage + (uint64_t) entryRVA;
    placeSoftwareBreakpoint ((void *) entryVA, false);
}
void debugger::checkInterruptEvent ()
{
    for (const auto & i : interruptingEvents) 
    {
        if (i == EXCEPTION_DEBUG_EVENT)
        {
            for (const auto & j : interruptingExceptions)
            {
                if (currentDebugEvent.u.Exception.ExceptionRecord.ExceptionCode == j)
                {
                    SetEvent (commandEvent);
                    WaitForSingleObject (continueDebugEvent,INFINITE);
                    // wait for command to be executed
                }
            }
        }
        else if (currentDebugEvent.dwDebugEventCode == i)
        {
            SetEvent (commandEvent);
            WaitForSingleObject (continueDebugEvent,INFINITE);
            // wait for command to be executed
        }
    }
}
DWORD debugger::run (std::string fileName)
{
    ResetEvent (commandEvent);
    ResetEvent (continueDebugEvent);

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    
    if (!CreateProcess (fileName.c_str(),NULL,NULL,NULL,TRUE,DEBUG_PROCESS,NULL,NULL,&si,&pi))
    {
       log ("Cannot start debugged process\n",logType::ERR, stdoutHandle);
       return 1;
    }

    debuggedProcessHandle = pi.hProcess;

    memHelper = new memoryHelper (debuggedProcessHandle, stdoutHandle);

    while (debuggingActive)
    {
        ZeroMemory ( &currentDebugEvent, sizeof(currentDebugEvent));

        if (!WaitForDebugEvent (&currentDebugEvent,INFINITE))
        {
            log ("WaitForDebugEven returned nonzero value\n",logType::ERR, stdoutHandle);
            return 2;
        }

        this->currentContext = getContext (CONTEXT_ALL);

        DWORD debugResponse = processDebugEvents(&currentDebugEvent, &debuggingActive);

        if (!bypassInterruptOnce)
        {
            checkInterruptEvent ();          
            setContext (this->currentContext);
            ContinueDebugEvent (currentDebugEvent.dwProcessId,currentDebugEvent.dwThreadId,debugResponse); 
        }
        else 
        {
            bypassInterruptOnce = false;
            setContext (this->currentContext);
            ContinueDebugEvent (currentDebugEvent.dwProcessId,currentDebugEvent.dwThreadId,debugResponse);
        }
    }
    return 0;
}
void debugger::showBreakpoints ()
{
    int j = 0;
    for (auto & i : breakpoints)
    {
        log ("Breakpoint [%d] address %.16llx oneHit %d hitCount %d\n",logType::INFO, stdoutHandle, j, i.getAddress(), i.getIsOneHit(), i.getHitCount());
        j++;
    }
}
bool debugger::deleteBreakpointByAddress (void * address)
{
    for (auto it = std::begin (breakpoints); it != std::end (breakpoints); ++it) 
    {
        if (it->getAddress() == address)
        {
            breakpoints.erase (it);
            return true;
        }
    }
    return false;
}
bool debugger::deleteBreakpointByIndex (uint64_t number)
{
    if (number < breakpoints.size())
    {
        breakpoints.erase (breakpoints.begin() + number);
    }
}
void debugger::setRegisterWithValue (std::string registerString, uint64_t value)
{
    if (registerString == "rax" | registerString == "RAX" )
    {
        currentContext.Rax = value;
    }
    else if (registerString == "rbx" | registerString == "RBX" )
    {
        currentContext.Rbx = value;
    }
    else if (registerString == "rcx" | registerString == "RCX" )
    {
        currentContext.Rcx = value;
    }
    else if (registerString == "rdx" | registerString == "RDX" )
    {
        currentContext.Rdx = value;
    }
    else if (registerString == "rbp" | registerString == "RBP" )
    {
        currentContext.Rbp = value;
    }
    else if (registerString == "rsp" | registerString == "RSP" )
    {
        currentContext.Rsp = value;
    }
    else if (registerString == "rdi" | registerString == "RDI" )
    {
        currentContext.Rdi = value;
    }
    else if (registerString == "rsi" | registerString == "RSI" )
    {
        currentContext.Rsi = value;
    }
    else if (registerString == "r8" | registerString == "R8" )
    {
        currentContext.R8 = value;
    }
    else if (registerString == "r9" | registerString == "R9" )
    {
        currentContext.R9 = value;
    }
    else if (registerString == "r10" | registerString == "R10" )
    {
        currentContext.R10 = value;
    }
    else if (registerString == "r11" | registerString == "R11" )
    {
        currentContext.R11 = value;
    }
    else if (registerString == "r12" | registerString == "R12" )
    {
        currentContext.R12 = value;
    }
    else if (registerString == "r13" | registerString == "R13" )
    {
        currentContext.R13 = value;
    }  
    else if (registerString == "r14" | registerString == "R14" )
    {
        currentContext.R14 = value;
    }  
    else if (registerString == "r15" | registerString == "R15" )
    {
        currentContext.R15 = value;
    }  
    else if (registerString == "rflags" | registerString == "RFLAGS" )
    {
        currentContext.EFlags = value;
    }              
}
HANDLE debugger::getCurrentThread ()
{
    return OpenThread (THREAD_GET_CONTEXT, FALSE, currentDebugEvent.dwThreadId);
}
std::string debugger::getFunctionNameForAddress (uint64_t address)
{
    for (const auto & func : functionNames)
    {
        if (address >= func.start && address <= func.end)
        {
            return func.name;
        }
    }
    return "?";
}
void debugger::showBacktrace ()
{
    // CaptureStackBackTrace
    //std::vector<CALLSTACKENTRY> callstackVector;
    const int MaxNameLen = 256;
    CONTEXT context = getContext(CONTEXT_CONTROL | CONTEXT_INTEGER);

    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    char name[MaxNameLen];
    char module[MaxNameLen];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

    DWORD64             displacement;

    DWORD disp;

    STACKFRAME64 frame;

    ZeroMemory(&frame, sizeof(STACKFRAME64));

    DWORD machineType = IMAGE_FILE_MACHINE_AMD64;

    frame.AddrPC.Offset = context.Rip;
    frame.AddrPC.Mode = AddrModeFlat;

    frame.AddrFrame.Offset = context.Rsp;
    frame.AddrFrame.Mode = AddrModeFlat;

    frame.AddrStack.Offset = context.Rsp; // ???? was csp like generic stack pointer
    frame.AddrStack.Mode = AddrModeFlat;

    const int MaxWalks = 50;
    // Container for each callstack entry (50 pre-allocated entries)
    //callstackVector.clear();
    //callstackVector.reserve(MaxWalks);

    HANDLE hThread = getCurrentThread ();
    if (hThread == NULL)
    {
        log ("Cannot get handle to current thread when backtracing\n", logType::ERR, stdoutHandle);
        return;
    }
    SymInitialize(debuggedProcessHandle, NULL, TRUE ); // ?????? 
    currentMemoryMap->updateMemoryMap ();

    for (int i = 0; i < MaxWalks; i++)
    {
        if(!StackWalk64(
                    machineType,
                    debuggedProcessHandle,
                    hThread,
                    &frame,
                    &context,
                    NULL,
                    SymFunctionTableAccess64,
                    SymGetModuleBase64,
                    NULL))
        {
            break;
        }

        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        SymFromAddr(debuggedProcessHandle, ( ULONG64 )frame.AddrPC.Offset, &displacement, pSymbol);
        size_t symbolNameSize = strlen (pSymbol->Name);

        std::string internalSymbolName = getFunctionNameForAddress(frame.AddrPC.Offset);

        if(frame.AddrPC.Offset != 0)
        {
            std::string sectionName = currentMemoryMap->getSectionNameForAddress (frame.AddrPC.Offset);
            std::string moduleName = currentMemoryMap->getImageNameForAddress(frame.AddrPC.Offset);

            printf ("#%d %.16llx <%s->%s> (%s)\n",
                    i,
                    frame.AddrPC.Offset,
                    moduleName.c_str(),
                    sectionName.c_str(),
                    (symbolNameSize == 0 ? internalSymbolName.c_str() : pSymbol->Name));
        }
        else
        {
            break;
        }
    }
}
void debugger::handleCommands(command * currentCommand)
{
    if (currentCommand->type == commandType::HELP)
    {
        printHelp ();
    }
    else if (currentCommand->type == commandType::CONTINUE && debuggingActive)
    {
        if (lastException.exceptionType == EXCEPTION_BREAKPOINT) // single_step after breakpoint restoring breakpoint but we do not want to interrupt that time
        {
            bypassInterruptOnce = true;
        }
        SetEvent (continueDebugEvent);
        commandModeActive = false;
    }
    else if (currentCommand->type == commandType::BACKTRACE)
    {
        showBacktrace ();
    }
    else if (currentCommand->type == commandType::SOFT_BREAKPOINT && debuggingActive)
    {
        void * breakpointAddress = parseStringToAddress(currentCommand->arguments[0].arg);
        placeSoftwareBreakpoint (breakpointAddress, false);
    }
    else if (currentCommand->type == commandType::WRITE_MEMORY_INT && debuggerActive)
    {
        void * address = parseStringToAddress (currentCommand->arguments[0].arg);
        uint32_t size = parseStringToNumber (currentCommand->arguments[1].arg, 10); // maximum 8 bytes
        uint64_t value = parseStringToNumber (currentCommand->arguments[2].arg, 16);
        memHelper->writeIntAt (value, address, size);
    }
    else if (currentCommand->type == commandType::SHOW_MEMORY_REGIONS && debuggingActive)
    {
        currentMemoryMap->updateMemoryMap ();
        currentMemoryMap->showMemoryMap ();
    }
    else if (currentCommand->type == commandType::SET_REGISTER && debuggingActive)
    {
        std::string registerString = currentCommand->arguments[0].arg;
        uint64_t value = parseStringToNumber (currentCommand->arguments[1].arg, 16);
        setRegisterWithValue (currentCommand->arguments[0].arg, value);
    }
    else if (currentCommand->type == commandType::HEXDUMP && debuggingActive)
    {
        void * address = parseStringToAddress (currentCommand->arguments[0].arg);
        uint32_t size = parseStringToNumber (currentCommand->arguments[1].arg, 10);
        memHelper->printHexdump (address, size);
    }
    else if (currentCommand->type == commandType::BREAKPOINT_DELETE)
    {
        if (currentCommand->arguments[0].type == argumentType::ADDRESS)
        {
            void * address = parseStringToAddress (currentCommand->arguments[0].arg);
            deleteBreakpointByAddress (address);
        }
        else if (currentCommand->arguments[0].type == argumentType::NUMBER)
        {
            int breakpointNumber = parseStringToNumber (currentCommand->arguments[0].arg, 10);
            deleteBreakpointByIndex (breakpointNumber);
        }
    }
    else if (currentCommand->type == commandType::DISASM && debuggingActive)
    {
        void * address = parseStringToAddress(currentCommand->arguments[0].arg);
        int numberOfInstructions = parseStringToNumber(currentCommand->arguments[1].arg, 10);

        disasmAt (address,numberOfInstructions);
    }
    else if (currentCommand->type == commandType::SHOW_BREAKPOINTS)
    {
        showBreakpoints ();
    }
    else if (currentCommand->type == commandType::RUN)
    {
        if (debuggingActive)
        {
            log ("The program is being debugged, exit and run it again\n",logType::WARNING, stdoutHandle);
        }
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
    else if (currentCommand->type == commandType::STEP_IN && debuggingActive)
    {
        this->currentContext.EFlags |= 0x100;
        SetEvent (continueDebugEvent);
        commandModeActive = false;
    }
    else if (currentCommand->type == commandType::NEXT_INSTRUCTION && debuggingActive)
    {
        if (lastException.exceptionType == EXCEPTION_BREAKPOINT && !lastException.oneHitBreakpoint) // single_step after breakpoint restoring breakpoint but we do not want to interrupt that time
        {
            bypassInterruptOnce = true;
        }
        void * addr = getNextInstructionAddress ( (void *) currentContext.Rip);
        if (addr)
        {
            placeSoftwareBreakpoint (addr, true);
        }
        else
        {
            log ("Problem with next instruction command\n", logType::ERR, stdoutHandle);
        }
        SetEvent (continueDebugEvent);
        commandModeActive = false;
    }
    else if (currentCommand->type == commandType::CONTEXT && debuggingActive)
    {
        showContext ();
    }
}
void debugger::interactiveCommands ()
{
    std::string c;
    while (debuggerActive)
    {
        WaitForSingleObject (commandEvent,INFINITE); 
        // interrupt reached
        if (debuggingActive)
        {
            showContext ();
        }
        
        commandModeActive = true;
        while (commandModeActive)
        {
            log ("",logType::PROMPT, stdoutHandle);
            std::getline(std::cin, c);
            command * currentCommand = parseCommand (c);

            if (currentCommand->type == commandType::UNKNOWN)
            {
                log ("Unknown command provided\n",logType::ERR, stdoutHandle);
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
void debugger::placeSoftwareBreakpoint (void * address, bool oneHit)
{
    breakpoint newBreakpoint (address, breakpointType::SOFTWARE_TYPE, oneHit);
    if (!newBreakpoint.set (debuggedProcessHandle))
    {
        log ("Cannot set breakpoint at %.16llx\n",logType::ERR,address, stdoutHandle,  address);
    }
    else
    {
        breakpoints.push_back (newBreakpoint);
    }
}

debugger::debugger (std::string fileName)
{
    interruptingEvents.insert(EXCEPTION_DEBUG_EVENT); // only exception interrupts execution
    interruptingExceptions.insert (EXCEPTION_BREAKPOINT);
    interruptingExceptions.insert (EXCEPTION_ACCESS_VIOLATION);
    interruptingExceptions.insert (EXCEPTION_ILLEGAL_INSTRUCTION);
    interruptingExceptions.insert (EXCEPTION_SINGLE_STEP);

    stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    commandEvent = CreateEventA (NULL,false,false,"commandEvent");
    continueDebugEvent = CreateEventA (NULL,false,false,"continueDebugEvent");
    this->fileName = fileName;
    debuggerThread = std::thread(debugger::run, this, fileName);
}
void debugger::handleSingleStep (EXCEPTION_DEBUG_INFO * exception, std::string sectionName, std::string moduleName)
{
    uint64_t breakpointAddress = (uint64_t) exception->ExceptionRecord.ExceptionAddress;
    breakpoint * bp = searchForBreakpoint (breakpoints, (void *) lastException.rip);

    if (bp && !bp->getIsOneHit() && lastException.exceptionType == EXCEPTION_BREAKPOINT)
    {
        lastException.oneHitBreakpoint = false;
        if (!bp->setAgain(debuggedProcessHandle))
        {
            log ("Cannot set breakpoint again (in single step exception)\n",logType::ERR, stdoutHandle);
        }
        this->currentContext.EFlags &= ~0x100;
    }
    else
    {
        lastException.oneHitBreakpoint = true;
        log ("User single step reached at 0x%.16llx <%s->%s>\n",logType::INFO, stdoutHandle, breakpointAddress, moduleName.c_str(), sectionName.c_str());
    }
    lastException.exceptionType = (DWORD) exception->ExceptionRecord.ExceptionCode;
    lastException.rip = breakpointAddress;
}
void debugger::handleBreakpoint (EXCEPTION_DEBUG_INFO * exception, std::string sectionName, std::string moduleName)
{
    uint64_t breakpointAddress = (uint64_t) exception->ExceptionRecord.ExceptionAddress;
    breakpoint * bp = searchForBreakpoint (breakpoints, (void *) breakpointAddress);

    if (bp && bp->getType() == breakpointType::SOFTWARE_TYPE) // user breakpoint
    {
        bp->incrementHitCount ();
        log ("User software breakpoint reached at 0x%.16llx <%s->%s>\n",logType::INFO, stdoutHandle, breakpointAddress, moduleName.c_str(), sectionName.c_str());
        if (!bp->restore(debuggedProcessHandle))// restore original byte to continue execution
        {
            log ("Cannot restore breakpoint at 0x%.16llx <%s->%s>\n",logType::INFO, stdoutHandle, breakpointAddress, moduleName.c_str(), sectionName.c_str());   
        }
        bp->getIsOneHit() == 0 ? currentContext.EFlags |= 0x100 : currentContext.EFlags &= ~0x100;
        bp->getIsOneHit() == 0 ? lastException.oneHitBreakpoint = 0 : lastException.oneHitBreakpoint = 1;
        if (bp->getIsOneHit())
        {
            printf ("One hit \n");
            breakpoints.erase(std::remove(breakpoints.begin(), breakpoints.end(), *bp), breakpoints.end());
        }
        lastException.exceptionType = (DWORD) exception->ExceptionRecord.ExceptionCode;
        lastException.rip = breakpointAddress;

        this->currentContext.Rip--; // int3 already consumed, need to revert execution state
    }
    else // system breakpoint
    {
        log ("System breakpoint reached at 0x%.16llx <%s->%s>\n", logType::INFO, stdoutHandle, breakpointAddress, moduleName.c_str(), sectionName.c_str());
    }    
}
DWORD debugger::processCreateProcess (DEBUG_EVENT * event)
{
    CREATE_PROCESS_DEBUG_INFO * info = &event->u.CreateProcessInfo;
    char * modulePath = new char [MAX_PATH + 1];
    GetFinalPathNameByHandleA () (info->hFile,modulePath,MAX_PATH+1,0);
    std::string moduleNameString ( (const char *) modulePath);
    char * moduleName = PathFindFileNameA(modulePath + 4);

    debuggedProcessBaseAddress = (uint64_t) info->lpBaseOfImage;
    checkWOW64 ();
    currentMemoryMap = new memoryMap (debuggedProcessHandle, wow64);
    
    if (!parseSymbols (moduleNameString))
    {
        // parse IAT names
    }
    PEparser parser (moduleNameString);
    std::string entrypointSectionName = parser.getSectionNameForAddress ((uint64_t)info->lpStartAddress - (uint64_t)info->lpBaseOfImage); 
    log ("%s loaded, base 0x%.16llx entrypoint 0x%.16llx <%.8s>\n",logType::INFO, stdoutHandle, moduleName, info->lpBaseOfImage, info->lpStartAddress, entrypointSectionName.c_str());

    breakpointEntryPoint (info);

    delete [] modulePath;
    return DBG_CONTINUE;
}
DWORD debugger::processExceptions (DEBUG_EVENT * event)
{
    EXCEPTION_DEBUG_INFO * exception = &event->u.Exception;
    if (exception->ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT && exception->ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP)
    {
        if (exception->dwFirstChance)
        {
            log ("First chance ", logType::ERR, stdoutHandle);
        }
        else if (!exception->dwFirstChance)
        {
            log ("Last chance ", logType::ERR, stdoutHandle);
        }   
    }
    currentMemoryMap->updateMemoryMap ();
    std::string sectionName = currentMemoryMap->getSectionNameForAddress ((uint64_t) exception->ExceptionRecord.ExceptionAddress);
    std::string moduleName = currentMemoryMap->getImageNameForAddress((uint64_t) exception->ExceptionRecord.ExceptionAddress);
    switch (exception->ExceptionRecord.ExceptionCode)
    {
        case EXCEPTION_ACCESS_VIOLATION:
        {
            printf ("Access Violation (0x%.08x) at 0x%.16llx <%s->%s>\n",
                    exception->ExceptionRecord.ExceptionCode,
                    exception->ExceptionRecord.ExceptionAddress,
                    moduleName.c_str(),
                    sectionName.c_str()
                    );
            return DBG_EXCEPTION_NOT_HANDLED;
        }
        case EXCEPTION_BREAKPOINT:
        {
            handleBreakpoint (exception, sectionName, moduleName);
            return DBG_CONTINUE;
        }
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        {
            printf ("Division by zero exception at 0x%.16llx <%s->%s>\n",
                    exception->ExceptionRecord.ExceptionAddress,
                    moduleName.c_str(),
                    sectionName.c_str()
                   );
            return DBG_EXCEPTION_NOT_HANDLED;
        }
        case EXCEPTION_PRIV_INSTRUCTION:
        {
            printf ("Privileged instruction was spotted at 0x%.16llx <%s->%s>\n",
                    exception->ExceptionRecord.ExceptionAddress,
                    moduleName.c_str(),
                    sectionName.c_str()
                   );  
            return DBG_EXCEPTION_NOT_HANDLED;
        }
        case EXCEPTION_SINGLE_STEP:
        {
            handleSingleStep (exception, sectionName, moduleName);
            return DBG_CONTINUE;
        }
        default:
        {
            log ("Not implemented exception yet at 0x%.16llx <%s->%s>\n",
                 logType::UNKNOWN_EVENT,
                 stdoutHandle,exception->ExceptionRecord.ExceptionAddress,
                 moduleName.c_str(),
                 sectionName.c_str()
                );
            return DBG_EXCEPTION_NOT_HANDLED;
        }
    }
}
bool debugger::parseSymbols (std::string filePath) // parse COFF symbols from PE reading it from disk
{
    // UnDecorateSymbolName

    PEparser parser (filePath);
    uint32_t coffTableOffset = parser.getCoffSymbolTableOffset ();
    uint32_t coffSymbolNumber = parser.getCoffSymbolNumber ();
    if (coffSymbolNumber > 0 && coffTableOffset != 0)
    {
        log ("Found %i COFF symbols, parsing them\n",logType::INFO, stdoutHandle, coffSymbolNumber);

        coffSymbolParser symbolParser;
        std::vector <COFFentry> entries = parser.getCoffEntries();
        auto extendedNames = parser.getCoffExtendedNames();
        uint64_t coffExtendedNamesOffset = parser.getCoffExtendedNamesOffset();
        COFFsymbols = symbolParser.parseSymbols (parser.getCoffEntries (), extendedNames, coffExtendedNamesOffset, parser);

        std::vector <RUNTIME_FUNCTION> functionRanges = parser.getPdataEntries ();
        if (functionRanges.size() == 0)
        {
            return true;
        }

        for (const auto & range : functionRanges)
        {
            if (COFFsymbols.find(range.BeginAddress) != COFFsymbols.end())
            {
                function newFunction;
                newFunction.name = COFFsymbols[range.BeginAddress].name;
                newFunction.start = range.BeginAddress + debuggedProcessBaseAddress;
                newFunction.end = range.EndAddress + debuggedProcessBaseAddress;

                functionNames.push_back (newFunction);
                //printf ("%s ", COFFsymbols[range.BeginAddress].name.c_str());
            }
            
            //printf ("%.16llx - %.16llx \n", debuggedProcessBaseAddress+range.BeginAddress, debuggedProcessBaseAddress+range.EndAddress);
        }
        /*
        
        for ( auto const& [key, val] : COFFsymbols )
        {
            fprintf (fw, "%i %.16llx --> %s\n", val.type, key, val.name.c_str());
            //printf ("%.16llx --> %s\n",key, val.c_str());
        }
        */

        return true;
    }
    return false;
}
DWORD debugger::processDebugEvents (DEBUG_EVENT * event, bool * debuggingActive) // returns dwContinueStatus 
{
    switch (event->dwDebugEventCode)
    {
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            return processCreateProcess (event);
        }
        case EXIT_PROCESS_DEBUG_EVENT:
        {
            std::lock_guard<std::mutex> l_debuggingActive (m_debuggingActive);

            EXIT_PROCESS_DEBUG_INFO * infoProc = &event->u.ExitProcess;
            log ("Process %u exited with code 0x%.08x\n", logType::INFO, stdoutHandle, event->dwProcessId, infoProc->dwExitCode);
            *debuggingActive = false;
            SetEvent (commandEvent);
            delete currentMemoryMap;
            delete memHelper;
            return DBG_CONTINUE;
        }
        case EXIT_THREAD_DEBUG_EVENT:
        {
            EXIT_THREAD_DEBUG_INFO * infoThread = &event->u.ExitThread;
            log ("Thread %u exited with code 0x%.08x\n", logType::THREAD, stdoutHandle, event->dwThreadId, infoThread->dwExitCode);
            return DBG_CONTINUE;
        }
        case CREATE_THREAD_DEBUG_EVENT:
        {
            CREATE_THREAD_DEBUG_INFO * infoThread = &event->u.CreateThread;
            currentMemoryMap->updateMemoryMap ();
            std::string sectionName = currentMemoryMap->getSectionNameForAddress ((uint64_t) infoThread->lpStartAddress);
            std::string moduleName = currentMemoryMap->getImageNameForAddress((uint64_t) infoThread->lpStartAddress);
            log ("Thread 0x%x created with entry address 0x%.16llx <%s->%s>\n", logType::THREAD, stdoutHandle, event->dwThreadId, infoThread->lpStartAddress, moduleName.c_str(), sectionName.c_str());
            return DBG_CONTINUE;
        }
        case LOAD_DLL_DEBUG_EVENT:
        {
            char * dllPath = (char *) malloc (MAX_PATH + 1);
            LOAD_DLL_DEBUG_INFO * loadInfo = &event->u.LoadDll;
            GetFinalPathNameByHandleA()(loadInfo->hFile,dllPath,MAX_PATH+1,0);
            char * dllName = PathFindFileNameA(dllPath + 4);
            log ("%s loaded (0x%.16llx)\n",logType::DLL, stdoutHandle, dllName, loadInfo->lpBaseOfDll);
            free (dllPath);
            return DBG_CONTINUE;
        }
        case UNLOAD_DLL_DEBUG_EVENT: // do not work with implicit loaded libraries ?
        {
            UNLOAD_DLL_DEBUG_INFO * unloadInfo = &event->u.UnloadDll;
            log ("0x%.16llx DLL unloaded\n",logType::DLL, stdoutHandle, unloadInfo->lpBaseOfDll);
            return DBG_CONTINUE;
        }
        case EXCEPTION_DEBUG_EVENT:
        {
            return processExceptions (event);
        }
        default:
        {
            log ("Not implemented debug event yet \n", logType::UNKNOWN_EVENT, stdoutHandle);
            return DBG_EXCEPTION_NOT_HANDLED;
        }
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}
void debugger::checkWOW64 ()

{
    if (!IsWow64Process (debuggedProcessHandle, &wow64))
    {
        log ("Cannot determine is process running under WOW64 subsystem by IsWow64Process() %s \n", logType::ERR, stdoutHandle);
        throw std::exception ();
    }
}

// MANUAL FUNCTIONS

void debugger::addSoftBreakpoint (void * address)
{
    if (!interactiveMode)
    {
        WaitForSingleObject (commandEvent,INFINITE);
        placeSoftwareBreakpoint (address, false);
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