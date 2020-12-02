#pragma once

#include <windows.h>
#include <inttypes.h>
#include <tlhelp32.h>
#include <vector>
#include "utils.h"
#include "structs.h"
#include "peParser.h"

typedef struct _PROCESS_BASIC_INFORMATION 
{
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

struct memoryProtection
{
	bool read = 0;
	bool write = 0;
	bool execute = 0;
	bool copy = 0;
	bool guard = 0;
	std::string toString ();
};
struct moduleData
{
    uint64_t VAaddress;
    std::string name;
    std::map <uint64_t, section> sections;
};

struct memoryRegion
{
	std::string name = "";
	uint64_t start;
	uint64_t size;
	memoryProtection protection; // when type is reserved protection is undefined
	std::string state;
	std::string type;
	std::string toString ();
	// access rights
};

struct baseRegion // e.g. all memory regions that belongs to specific module
{
	bool isIMG = false;
	std::string name = "";
	uint64_t base;
	std::vector <memoryRegion> memRegions;
};

class memoryMap
{
	private:
		HANDLE processHandle;
		HANDLE stdoutHandle;
		std::vector <baseRegion> baseRegions;
		int is32bit;

		void setProtectStateType (MEMORY_BASIC_INFORMATION mbi, memoryRegion *);
		DWORD memoryProtectionToDWORD (memoryProtection);
		std::vector <moduleData> getModulesLoaded ();
		std::string stateForAddr (uint64_t);
		std::string typeForAddr (uint64_t);
	public:
		memoryMap (HANDLE, int);
		void * getPEBaddr ();
		void updateMemoryMap ();
		void showMemoryMap ();
		void setProtection (uint64_t, uint64_t, memoryProtection);
		std::string getSectionNameForAddress (uint64_t);
		std::string getImageNameForAddress (uint64_t);
		memoryProtection protectionForAddr (uint64_t addr);
		std::vector <uint64_t> getModulesAddr ();

};

class memoryHelper
{
	private:
		HANDLE processHandle;
		HANDLE stdoutHandle;
		static constexpr int hexdumpWidth = 8;
	public:
		memoryHelper (HANDLE, HANDLE);
		bool printHexdump (void *, uint32_t);
		bool writeIntAt (uint64_t, void *, uint32_t);
				
};