// cmake -G "MinGW Makefiles" .. -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_X86_SUPPORT=1

#include "debugger.h"
#include <capstone/capstone.h>

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int main (int argc, char ** argv)
{

	/* random capstone code to check is everything working */
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
	

	if (argc < 2)
    {
        printf ("[!] Usage: maldbg <exe>\n");
        return 1;
    }
    std::string debugged (argv[1]);
    debugger d (debugged);
    d.interactive ();
    
    return 0;
}