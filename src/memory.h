#pragma once

#include <windows.h>
#include <inttypes.h>
#include <vector>
#include "utils.h"

struct memoryRegion
{
	std::string name = "";
	uint64_t start;
	uint64_t size;
	std::string protection = "*****"; // when type is reserved protection is undefined
	std::string state;
	std::string type;
	// access rights
};
struct memoryProtection
{
	bool read = 0;
	bool write = 0;
	bool execute = 0;
	bool copy = 0;
	bool guard = 0;
	std::string toString ();
};

struct baseRegion // e.g. all memory regions that belongs to specific module
{
	std::string name = "";
	uint64_t base;
	std::vector <memoryRegion> memRegions;
};

class memoryMap
{
	private:
		std::vector <baseRegion> baseRegions;
	public:
		memoryMap ();
		void updateMemoryMap (HANDLE);
		void showMemoryMap (HANDLE);
		void setProtectStateType (MEMORY_BASIC_INFORMATION mbi, memoryRegion *);

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