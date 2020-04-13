#include <shlwapi.h>
#include <strsafe.h>
#include "debugger.h"

// vec.erase(std::remove(vec.begin(), vec.end(), 8), vec.end());


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

void * parseStringToAddress (std::string toConvert)
{
    void * address;
    sscanf (toConvert.c_str(),"%x", &address);
    return address;
}
int parseStringToNumber (std::string toConvert)
{
    int number;
    sscanf (toConvert.c_str(), "%i", &number);
    return number;
}
breakpoint * debugger::searchForBreakpoint (void * address)
{
    for (auto & i : breakpoints)
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
        log ("Cannot read memory at %.16llx\n",logType::ERR, ref);
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
        delete codeBuffer;
        return (void *) insn[1].address;
    }
    else
    {
        delete codeBuffer;
        return nullptr;
    }
    
}
void debugger::disasmAt (void * address, int numberOfInstructions)
{
    std::vector <breakpoint *> disassembledBreakpoints;
    uint8_t * codeBuffer = new uint8_t [100];
    if (!ReadProcessMemory (debuggedProcessHandle, (LPCVOID) address, codeBuffer, 100 , NULL))
    {
        log ("Cannot read memory at %.16llx\n",logType::ERR,address);
        return;
    }
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        return;
    }

    count = cs_disasm (handle, codeBuffer, 100 , (uint64_t)address, 0, &insn);
    if (count > 0)
    {
        for (int j = 0; j < (numberOfInstructions >= count ? count : numberOfInstructions); j++) // iterate over all instructions disassembled to find breakpoint locations
        {
            breakpoint * bp = searchForBreakpoint ( (void *) insn[j].address);
            if (bp)
            {
                disassembledBreakpoints.push_back (bp); // even if breakpoint is not restored yet or it is hardware it is displayed
            }
            if (!strncmp (insn[j].mnemonic, "int3", 4) && bp ) // if breakpoint is set and there is 0xcc byte 
            {
                printf ("Found int3 at %.16llx \n", insn[j].address);

                if (bp->getType() == breakpointType::SOFTWARE_TYPE) // user software breakpoint
                {
                    size_t int3Offset = insn[j].address - (uint64_t) address;
                    codeBuffer [int3Offset] = bp->getOriginalByte();
                    cs_free (insn, count);
                    count = cs_disasm (handle, codeBuffer, 100 , (uint64_t) address, 0, &insn); // disassembly again
                }
            }
        }
        for (int j = 0 ; j < (numberOfInstructions >= count ? count : numberOfInstructions); j++)
        {
            bool breakpointShown = false;
            for (const auto & a : disassembledBreakpoints) // search for line with breakpoint
            {
                if ((void *) insn[j].address == a->getAddress() && a->getType() == breakpointType::SOFTWARE_TYPE && !a->getIsOneHit())
                {
                    printfColor ("0x%.16llx:\t%s\t\t%s\n", 12, insn[j].address, insn[j].mnemonic, insn[j].op_str); // breakpoint line spotted
                    breakpointShown = true;
                }
                else if ((void *) insn[j].address == a->getAddress() && a->getType() == breakpointType::HARDWARE_TYPE)
                {
                    printfColor ("0x%.16llx:\t%s\t\t%s\n", 9, insn[j].address, insn[j].mnemonic, insn[j].op_str);
                    breakpointShown = true;
                }
            }
            if (!breakpointShown) // if line is not breakpoint print it normally
            {
                printf ("0x%.16llx:\t%s\t\t%s\n",insn[j].address, insn[j].mnemonic, insn[j].op_str);
            }
        }
        cs_free (insn, count);
    }
    else
    {
        log ("Cannot disassembly memory at %.16llx\n",logType::ERR, address);
    }
    cs_close (&handle);
    delete codeBuffer;
}
CONTEXT * debugger::getContext ()
{
    CONTEXT * lcContext = new CONTEXT;
    lcContext->ContextFlags = CONTEXT_ALL;
    HANDLE threadHandle = OpenThread (THREAD_GET_CONTEXT, FALSE, currentDebugEvent.dwThreadId);
    if (threadHandle == NULL)
    {
        log ("Cannot get handle to thread that caused exception",logType::ERR);
        return NULL;
    }
    if (!GetThreadContext(threadHandle, lcContext))
    {
        log ("Cannot get thread context that caused exception",logType::ERR);
        return NULL;
    }
    return lcContext;
}
void debugger::setContext (CONTEXT * context)
{
    HANDLE threadHandle = OpenThread (THREAD_SET_CONTEXT, FALSE, currentDebugEvent.dwThreadId);
    if (!SetThreadContext(threadHandle, context))
    {
        log ("Cannot set thread context",logType::ERR);
        return;
    }
}
void debugger::showContext ()
{
    CONTEXT * lcContext = this->currentContext;

    printf ("\n");

    DWORD flg = lcContext->EFlags;

    log ("RAX %.16llx RBX %.16llx RCX %.16llx\nRDX %.16llx RSI %.16llx RDI %.16llx",logType::CONTEXT_REGISTERS,
        lcContext->Rax, lcContext->Rbx, lcContext->Rcx, lcContext->Rdx, lcContext->Rsi, lcContext->Rdi);
    log ("R8  %.16llx R9  %.16llx R10 %.16llx\nR11 %.16llx R12 %.16llx R13 %.16llx\nR14 %.16llx R15 %.16llx FLG %.16llx",logType::CONTEXT_REGISTERS,
        lcContext->R8, lcContext->R9, lcContext->R10, lcContext->R11, lcContext->R12, lcContext->R13, lcContext->R14, lcContext->R15, lcContext->EFlags);
    log ("RIP %.16llx RBP %.016x RSP %.016x", logType::CONTEXT_REGISTERS, lcContext->Rip, lcContext->Rbp, lcContext->Rsp);

    log ("ZF %.1x CF %.1x PF %.1x AF %.1x SF %.1x TF %.1x IF %.1x DF %.1x OF %.1x",logType::CONTEXT_REGISTERS,
        (flg & (1 << 6)) >> 6, flg & 1, (flg & (1 << 2)) >> 2, (flg & (1 << 4)) >> 4, (flg & (1 << 7)) >> 7, (flg & (1 << 8)) >> 8,
        (flg & (1 << 9)) >> 9, (flg & (1 << 10)) >> 10, (flg & (1 << 11)) >> 11 );

    printf ("\n");

    disasmAt ((void *)lcContext->Rip, SHOW_CONTEXT_INSTRUCTION_COUNT);   

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
       log ("Cannot start debugged process\n",logType::ERR);
       return 1;
    }
    debuggedProcessHandle = pi.hProcess;
    while (debuggingActive)
    {
        ZeroMemory ( &currentDebugEvent, sizeof(currentDebugEvent));

        if (!WaitForDebugEvent (&currentDebugEvent,INFINITE))
        {
            log ("WaitForDebugEven returned nonzero value\n",logType::ERR);
            return 2;
        }

        this->currentContext = getContext ();
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
    delete this->currentContext;
    return 0;
}
command * parseCommand (std::string c)
{
    command * comm = new command ();

    std::regex continueRegex ("^(c|cont|continue)\\s*$");
    std::regex contextRegex ("^(context)$");
    std::regex runRegex ("^(r|run)\\s*$");
    std::regex exitRegex ("^(e|exit)\\s*$");
    std::regex softBreakpointRegex ("^(b|br|bp|breakpoint)\\s+(0x)?([0-9a-fA-F]+)\\s*$");
    std::regex disasmRegex ("^(disasm|disassembly)\\s+(0x)?([0-9a-fA-F]+)\\s+((0x[0-9a-fA-F]+)|([0-9]+))$");
    std::regex stepInRegex ("^(si|step in|s i)\\s*$");
    std::regex nextInstructionRegex ("^(ni|next instruction|n i)\\s*$");
    std::regex showBreakpointsRegex ("^(bl|show breakpoints|b l|b list)\\s*$");
    std::regex removeBreakpointRegex ("^(bd|b delete|breakpoint delete)\\s+(([0-9]+)|0x([0-9a-fA-F]+))$");
    // |(0x[0-9a-fA-F]+)
    // \\s+([0-9]+)\\s*
    std::smatch continueMatches;
    std::smatch contextMatches;
    std::smatch runMatches;
    std::smatch exitMatches;
    std::smatch softBreakpointMatches;
    std::smatch disasmMatches;
    std::smatch stepInMatches;
    std::smatch nextInstructionMatches;
    std::smatch showBreakpointsMatches;
    std::smatch removeBreakpointMatches;


    if (std::regex_search (c, continueMatches, continueRegex))
    {
        comm->type = commandType::CONTINUE;
        return comm;
    }
    else if (std::regex_search (c, stepInMatches, stepInRegex))
    {
        comm->type = commandType::STEP_IN;
        return comm;
    }
    else if (std::regex_search (c, nextInstructionMatches, nextInstructionRegex))
    {
        comm->type = commandType::NEXT_INSTRUCTION;    
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
    else if (std::regex_search (c, contextMatches, contextRegex))
    {
        comm->type = commandType::CONTEXT;
        return comm;   
    }
    else if (std::regex_search (c, showBreakpointsMatches, showBreakpointsRegex))
    {
        comm->type = commandType::SHOW_BREAKPOINTS;
        return comm;
    }
    else if (std::regex_match (c, softBreakpointMatches, softBreakpointRegex))
    {
        comm->type = commandType::SOFT_BREAKPOINT;
        comm->arguments.push_back ( {argumentType::ADDRESS,softBreakpointMatches[3].str()} );
        return comm;
    }
    else if (std::regex_match (c, removeBreakpointMatches, removeBreakpointRegex))
    {
        comm->type = commandType::BREAKPOINT_DELETE;
        if (removeBreakpointMatches[3].str().length() > 0)
        {
            comm->arguments.push_back ( {argumentType::NUMBER, removeBreakpointMatches[2].str()} );
        }
        else if (removeBreakpointMatches[4].str().length() > 0)
        {
            comm->arguments.push_back ( {argumentType::ADDRESS, removeBreakpointMatches[4].str()} );
        }
        return comm;
    }
    else if (std::regex_match (c, disasmMatches, disasmRegex))
    {
        comm->type = commandType::DISASM;
        /*
        // code for testing regexes

        for (int i = 0; i < disasmMatches.size(); i++)
        {
            printf ("%i --> %s\n",i,disasmMatches[i].str().c_str());
        }
        */
        comm->arguments.push_back ( {argumentType::ADDRESS, disasmMatches[3].str()} );
        comm->arguments.push_back ( {argumentType::NUMBER, disasmMatches[4].str()} );
        return comm;
    }

    comm->type = commandType::UNKNOWN;
    return comm;
}
void debugger::showBreakpoints ()
{
    int j = 0;
    for (auto & i : breakpoints)
    {
        log ("Breakpoint [%d] address %.16llx oneHit %d hitCount %d\n",logType::INFO, j, i.getAddress(), i.getIsOneHit(), i.getHitCount());
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
void debugger::handleCommands(command * currentCommand)
{
    if (currentCommand->type == commandType::CONTINUE)
    {
        if (lastException.exceptionType == EXCEPTION_BREAKPOINT) // single_step after breakpoint restoring breakpoint but we do not want to interrupt that time
        {
            bypassInterruptOnce = true;
        }
        SetEvent (continueDebugEvent);
        commandModeActive = false;
    }
    else if (currentCommand->type == commandType::SOFT_BREAKPOINT)
    {
        void * breakpointAddress = parseStringToAddress(currentCommand->arguments[0].arg);
        placeSoftwareBreakpoint (breakpointAddress, false);
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
            int breakpointNumber = parseStringToNumber (currentCommand->arguments[0].arg);
            deleteBreakpointByIndex (breakpointNumber);
        }
    }
    else if (currentCommand->type == commandType::DISASM)
    {
        void * address = parseStringToAddress(currentCommand->arguments[0].arg);
        int numberOfInstructions = parseStringToNumber(currentCommand->arguments[1].arg);
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
    else if (currentCommand->type == commandType::STEP_IN)
    {
        this->currentContext->EFlags |= 0x100;
        SetEvent (continueDebugEvent);
        commandModeActive = false;
    }
    else if (currentCommand->type == commandType::NEXT_INSTRUCTION)
    {
        if (lastException.exceptionType == EXCEPTION_BREAKPOINT && !lastException.oneHitBreakpoint) // single_step after breakpoint restoring breakpoint but we do not want to interrupt that time
        {
            bypassInterruptOnce = true;
        }
        void * addr = getNextInstructionAddress ( (void *) currentContext->Rip);
        if (addr)
        {
            placeSoftwareBreakpoint (addr, true);
        }
        else
        {
            log ("Problem with next instruction command\n", logType::ERR);
        }
        SetEvent (continueDebugEvent);
        commandModeActive = false;
    }
    else if (currentCommand->type == commandType::CONTEXT)
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
        showContext ();
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
void debugger::printfColor (const char * format, DWORD color, ... )
{
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD savedAttributes;
    GetConsoleScreenBufferInfo(stdoutHandle, &consoleInfo);
    savedAttributes = consoleInfo.wAttributes;
    SetConsoleTextAttribute(stdoutHandle, color);
    va_list args;
    va_start(args, color);
    vprintf (format,args); // vprintf when we do not know how many arguments we gonna pass
    va_end (args);
    SetConsoleTextAttribute(stdoutHandle, savedAttributes);
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
        case logType::CONTEXT_REGISTERS:
        {
            va_list args;
            va_start(args, type);
            vprintf (messageFormatted,args); // vprintf when we do not know how many arguments we gonna pass
            va_end (args);
            SetConsoleTextAttribute(stdoutHandle, savedAttributes);
            printf ("\n");
            return;
        }
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
void debugger::placeSoftwareBreakpoint (void * address, bool oneHit)
{
    breakpoint newBreakpoint (address, breakpointType::SOFTWARE_TYPE, oneHit);
    if (!newBreakpoint.set (debuggedProcessHandle))
    {
        log ("Cannot set breakpoint at %.16llx\n",logType::ERR,address, address);
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
void debugger::handleSingleStep (EXCEPTION_DEBUG_INFO * exception)
{
    uint64_t breakpointAddress = (uint64_t) exception->ExceptionRecord.ExceptionAddress;
    breakpoint * bp = searchForBreakpoint ((void *) lastException.rip);

    if (bp && !bp->getIsOneHit() && lastException.exceptionType == EXCEPTION_BREAKPOINT)
    {
        lastException.oneHitBreakpoint = false;
        if (!bp->setAgain(debuggedProcessHandle))
        {
            log ("Cannot set breakpoint again (in single step exception)\n",logType::ERR);
        }
        this->currentContext->EFlags &= ~0x100;
    }
    else
    {
        lastException.oneHitBreakpoint = true;
        log ("User single step reached at 0x%.16llx\n",logType::INFO,breakpointAddress);
    }
    lastException.exceptionType = (DWORD) exception->ExceptionRecord.ExceptionCode;
    lastException.rip = breakpointAddress;
}
void debugger::handleBreakpoint (EXCEPTION_DEBUG_INFO * exception)
{
    uint64_t breakpointAddress = (uint64_t) exception->ExceptionRecord.ExceptionAddress;
    breakpoint * bp = searchForBreakpoint ( (void *) breakpointAddress);
    if (bp && bp->getType() == breakpointType::SOFTWARE_TYPE) // user breakpoint
    {
        bp->incrementHitCount ();
        log ("User software breakpoint reached at 0x%.16llx\n",logType::INFO,breakpointAddress);
        if (!bp->restore(debuggedProcessHandle))// restore original byte to continue execution
        {
            log ("Cannot restore breakpoint at 0x%.16llx\n",logType::INFO,breakpointAddress);   
        }
        bp->getIsOneHit() == 0 ? currentContext->EFlags |= 0x100 : currentContext->EFlags &= ~0x100;
        bp->getIsOneHit() == 0 ? lastException.oneHitBreakpoint = 0 : lastException.oneHitBreakpoint = 1;
        lastException.exceptionType = (DWORD) exception->ExceptionRecord.ExceptionCode;
        lastException.rip = breakpointAddress;

        this->currentContext->Rip--; // int3 already consumed, need to revert execution state
    }
    else // system breakpoint
    {
        log ("System breakpoint reached at 0x%.16llx\n", logType::INFO, breakpointAddress);
    }    
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
            printf ("Access Violation (0x%.08x) at 0x%.16llx\n",exception->ExceptionRecord.ExceptionCode, exception->ExceptionRecord.ExceptionAddress);
            return DBG_EXCEPTION_NOT_HANDLED;
        }
        case EXCEPTION_BREAKPOINT:
        {
            handleBreakpoint (exception);
            return DBG_CONTINUE;
        }
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        {
            printf ("Division by zero exception at 0x%.16llx\n",exception->ExceptionRecord.ExceptionAddress);
            return DBG_EXCEPTION_NOT_HANDLED;
        }
        case EXCEPTION_PRIV_INSTRUCTION:
        {
            printf ("Privileged instruction was spotted at 0x%.16llx\n",exception->ExceptionRecord.ExceptionAddress);  
            return DBG_EXCEPTION_NOT_HANDLED;
        }
        case EXCEPTION_SINGLE_STEP:
        {
            handleSingleStep (exception);
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
            log ("%s loaded, base 0x%.16llx entrypoint 0x%.16llx\n",logType::INFO,moduleName, info->lpBaseOfImage, info->lpStartAddress);
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
            log ("Thread 0x%x created with entry address 0x%.16llx\n", logType::THREAD, event->dwThreadId, infoThread->lpStartAddress);
            return DBG_CONTINUE;
        }
        case LOAD_DLL_DEBUG_EVENT:
        {
            char * dllPath = (char *) malloc (MAX_PATH + 1);
            LOAD_DLL_DEBUG_INFO * loadInfo = &event->u.LoadDll;
            GetFinalPathNameByHandleA()(loadInfo->hFile,dllPath,MAX_PATH+1,0);
            char * dllName = PathFindFileNameA(dllPath + 4);
            log ("%s loaded (0x%.16llx)\n",logType::DLL,dllName,loadInfo->lpBaseOfDll);
            free (dllPath);
            return DBG_CONTINUE;
        }
        case UNLOAD_DLL_DEBUG_EVENT: // do not work with implicit loaded libraries ?
        {
            UNLOAD_DLL_DEBUG_INFO * unloadInfo = &event->u.UnloadDll;
            log ("0x%.16llx DLL unloaded\n",logType::DLL,unloadInfo->lpBaseOfDll);
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