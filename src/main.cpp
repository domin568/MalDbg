#include "debugger.h"

int main (int argc, char ** argv)
{
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