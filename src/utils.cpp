#include "utils.h"

void printfColor (const char * format, DWORD color, HANDLE stdoutHandle, ...)
{
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD savedAttributes;
    GetConsoleScreenBufferInfo(stdoutHandle, &consoleInfo);
    savedAttributes = consoleInfo.wAttributes;
    SetConsoleTextAttribute(stdoutHandle, color);
    va_list args;
    va_start(args, stdoutHandle);
    vprintf (format,args); // vprintf when we do not know how many arguments we gonna pass
    va_end (args);
    SetConsoleTextAttribute(stdoutHandle, savedAttributes);
}
void log (const char * messageFormatted, logType type, HANDLE stdoutHandle, ...)
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
            va_start(args, stdoutHandle);
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
            printf ("%s","maldbg> ");
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
    va_start(args, stdoutHandle);
    vprintf (messageFormatted,args); // vprintf when we do not know how many arguments we gonna pass
    va_end (args);
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
    std::regex memoryMappingsRegex ("^(vmmap|memory mappings|map)\\s*$");
    std::regex hexdumpRegex ("^(h|hexdump|hex)\\s+0x([0-9a-fA-F]+)\\s+([0-9]+)\\s*$");
    std::regex setRegistersRegex ("^(sr|set register)\\s+((R|r)(ax|AX|bx|BX|cx|CX|dx|DX|bp|BP|sp|SP|si|SI|di|DI|8|9|10|11|12|13|14|15|flags|FLAGS))\\s+(0x)?([0-9a-fA-F]+)\\s*$");
    std::regex writeMemoryRegex ("^(wm|write memory)\\s+((0x)([0-9a-fA-F]+))\\s+([0-9]+)\\s+((0x)?([0-9a-fA-F]+))");
    std::regex helpRegex ("^help\\s*$");
    std::smatch match;

    if (std::regex_search(c, match, helpRegex))
    {
        comm->type = commandType::HELP;
        return comm;
    }
    else if (std::regex_search (c, match, continueRegex))
    {
        comm->type = commandType::CONTINUE;
        return comm;
    }
    else if (std::regex_search (c, match, memoryMappingsRegex))
    {
        comm->type = commandType::SHOW_MEMORY_REGIONS;
        return comm;
    }
    else if (std::regex_search (c, match, stepInRegex))
    {
        comm->type = commandType::STEP_IN;
        return comm;
    }
    else if (std::regex_search (c, match, nextInstructionRegex))
    {
        comm->type = commandType::NEXT_INSTRUCTION;    
        return comm;
    }
    else if (std::regex_search (c, match, runRegex))
    {
        comm->type = commandType::RUN;
        return comm;   
    }
    else if (std::regex_search (c, match, exitRegex))
    {
        comm->type = commandType::EXIT;
        return comm;   
    }
    else if (std::regex_search (c, match, contextRegex))
    {
        comm->type = commandType::CONTEXT;
        return comm;   
    }
    else if (std::regex_search (c, match, showBreakpointsRegex))
    {
        comm->type = commandType::SHOW_BREAKPOINTS;
        return comm;
    }
    else if (std::regex_match(c, match, writeMemoryRegex))
    {
        comm->type = commandType::WRITE_MEMORY_INT;

        comm->arguments.push_back ( { argumentType::ADDRESS, match[4].str() } );
        comm->arguments.push_back ( { argumentType::NUMBER, match[5].str() } );
        comm->arguments.push_back ( { argumentType::HEX_NUMBER, match[8].str() } );
        return comm;
    }
    else if (std::regex_match (c, match, setRegistersRegex))
    {
        comm->type = commandType::SET_REGISTER;
        comm->arguments.push_back ( { argumentType::STRING, match[2].str() } );
        comm->arguments.push_back ( { argumentType::HEX_NUMBER, match[6].str() } );
        return comm;
    }
    else if (std::regex_match (c, match, softBreakpointRegex))
    {
        comm->type = commandType::SOFT_BREAKPOINT;
        comm->arguments.push_back ( {argumentType::ADDRESS, match[3].str()} );
        return comm;
    }
    else if (std::regex_match (c, match, removeBreakpointRegex))
    {
        comm->type = commandType::BREAKPOINT_DELETE;
        if (match[3].str().length() > 0)
        {
            comm->arguments.push_back ( {argumentType::NUMBER, match[2].str()} );
        }
        else if (match[4].str().length() > 0)
        {
            comm->arguments.push_back ( {argumentType::ADDRESS, match[4].str()} );
        }
        return comm;
    }
    else if (std::regex_match (c, match, disasmRegex))
    {
        comm->type = commandType::DISASM;
        comm->arguments.push_back ( {argumentType::ADDRESS, match[3].str()} );
        comm->arguments.push_back ( {argumentType::NUMBER, match[4].str()} );
        return comm;
    }
    else if (std::regex_match (c, match, hexdumpRegex))
    {
        comm->type = commandType::HEXDUMP;
        comm->arguments.push_back ( {argumentType::ADDRESS, match[2].str()} );
        comm->arguments.push_back ( {argumentType::NUMBER, match[3].str()} );
        return comm;
    }

    /*
    for (int i = 0; i < match.size(); i++)
    {
        printf ("%i --> %s\n",i,match[i].str().c_str());
    }
    */

    comm->type = commandType::UNKNOWN;
    return comm;
}

void* parseStringToAddress (std::string toConvert)
{
    void * address;
    sscanf (toConvert.c_str(),"%x", &address);
    return address;
}
int parseStringToNumber (std::string toConvert, int base = 10)
{
    int number;
    if (base == 10)
    {
        sscanf (toConvert.c_str(), "%i", &number);
    }
    else if (base == 16)
    {
        sscanf (toConvert.c_str(), "%x", &number);
    }
    return number;
}
void printHelp ()
{
    puts ("r, run - run or restart program\n");
    puts ("breakpoint, b, bp, br <hex address> - place int3 breakpoint\n");
    puts ("context - show context of current thread\n");
    puts("disasm, disassembly <hex address> <count_decimal> - disassembly code at given address\n");
    puts ("continue, c - continue execution of program\n");
    puts ("exit, e - exit from debugger\n");
    puts ("step in, si, s i - step in by single instruction\n");
    puts ("next instruction, ni, n i - step by single instruction\n");
    puts ("show breakpoints, bl, breakpoint list - show active breakpoints\n");
    puts ("breakpoint delete, bd, b delete <index/hex address> - delete breakpoint by index (obtained by bl) or address\n");
    puts ("memory mappings, vmmap, map - show map of whole virtual memory for this process\n");
    puts ("hexdump, hex, h <hex address> <size_decimal>\n");
    puts ("set register, sr <register name> <hex value> - sets specified register with given value\n");
    puts ("write memory, wm <hex address> <size_decimal> <hex value>\n");
}