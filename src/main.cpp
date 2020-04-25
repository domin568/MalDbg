// DBG_CONTROL_C
#include "debugger.h"

int main (int argc, char ** argv)
{
	if (argc < 2)
    {
        printf ("[!] Usage: maldbg <exe>\n");
        return 1;
    }
    std::string debugged (argv[1]);
    try
    {
    	debugger d (debugged);
    	d.interactive ();
    }
    catch (std::exception)
    {
    	return 1;
    } 
    return 0;
}