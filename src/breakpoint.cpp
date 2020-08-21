#include "breakpoint.h"

breakpoint::breakpoint (void * address, breakpointType type, bool isOneHit, bool apiLog)
{
	this->type = type;
	this->address = address;
	this->isOneHit = isOneHit;
    this->apiLog = apiLog;
    hitCount = 0;
}
void breakpoint::incrementHitCount ()
{
	hitCount++;
}
bool breakpoint::operator== (const breakpoint & other)
{
    if ((uint64_t) address == (uint64_t) other.address && type == other.type)
    {
        return true;
    }
    return false;
}
bool breakpoint::set (HANDLE procHandle)
{
	if (type == breakpointType::SOFTWARE_TYPE)
	{
    	uint8_t int3Byte = 0xcc;
    	if (!ReadProcessMemory (procHandle, (LPCVOID) address, &originalByte, 1, NULL))
    	{
    	    return false;
    	}
    	if (!WriteProcessMemory (procHandle, (LPVOID) address, &int3Byte, 1, NULL))
    	{
    	    return false;
    	}
    	FlushInstructionCache(procHandle, (LPVOID) address, 1);
    	return true;
	}
	else if (type == breakpointType::HARDWARE_TYPE)
	{

	}
}
bool breakpoint::setAgain (HANDLE procHandle)
{
	if (type == breakpointType::SOFTWARE_TYPE)
	{
		uint8_t int3Byte = 0xCC;
        if (WriteProcessMemory (procHandle, (LPVOID) address, &int3Byte, 1, NULL) == 0) // restore stolen byte
        {
            return false;
        }
        FlushInstructionCache(procHandle, (LPVOID) address, 1);
        return true;
	}
}
bool breakpoint::restore (HANDLE procHandle)
{
	if (type == breakpointType::SOFTWARE_TYPE)
	{
        if (WriteProcessMemory (procHandle, (LPVOID) address, &originalByte, 1, NULL) == 0) // restore stolen byte
        {
            return false;
        }
        FlushInstructionCache(procHandle, (LPVOID) address, 1);
        return true;
	}
}