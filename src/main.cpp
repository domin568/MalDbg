#include "debugger.h"

int main (int argc, char ** argv)
{
    debugger d (argv[1]);
    d.run ();
    return 0;
}