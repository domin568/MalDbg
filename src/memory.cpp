#include "memory.h"

std::string memoryProtection::toString ()
{
	return (read == 1 ? std::string("R") : std::string("-")) + (write == 1 ? std::string("W") : std::string("-")) + (execute == 1 ? std::string("X") : std::string("-")) + (copy == 1 ? std::string("C") : std::string("-")) + (guard == 1 ? std::string("G") : std::string("-"));
}

memoryMap::memoryMap ()
{

}
void memoryMap::setProtectStateType (MEMORY_BASIC_INFORMATION mbi, memoryRegion * region)
{
	if (mbi.Type == MEM_IMAGE)
	{
		region->type = "IMG";
	}
	else if (mbi.Type == MEM_MAPPED)
	{
		region->type = "MAP";
	}
	else if (mbi.Type == MEM_PRIVATE)
	{
		region->type = "PRV";
	}

	if (mbi.State == MEM_COMMIT)
	{
		region->state = "COMMITED";

		memoryProtection prot; 

		if (mbi.Protect & PAGE_READONLY) // only one of them must me specified
		{
			prot.read = 1;
		}
		else if (mbi.Protect & PAGE_READWRITE)
		{
			prot.read = 1;
			prot.write = 1;
		}
		else if (mbi.Protect & PAGE_WRITECOPY)
		{
			prot.read = 1;
			prot.write = 1;
			prot.copy = 1;
		}
		else if (mbi.Protect & PAGE_EXECUTE)
		{
			prot.execute = 1;
		}
		else if (mbi.Protect & PAGE_EXECUTE_READ)
		{
			prot.execute = 1;
			prot.read = 1;
		}
		else if (mbi.Protect & PAGE_EXECUTE_READWRITE)
		{
			prot.read = 1;
			prot.write = 1;
			prot.execute = 1;
		}
		else if (mbi.Protect & PAGE_EXECUTE_WRITECOPY)
		{
			prot.read = 1;
			prot.write = 1;
			prot.execute = 1;
			prot.copy = 1;
		}

		if (mbi.Protect & PAGE_GUARD)
		{
			prot.guard = 1;
		}

		region->protection = prot.toString ();
	}
	else if (mbi.State == MEM_RESERVE)
	{
		region->state = "RESERVED";
	}
}
void memoryMap::updateMemoryMap (HANDLE processHandle)
{
	baseRegions.clear ();
	MEMORY_BASIC_INFORMATION mbi;

	size_t bytesReturned;
	uint64_t pageStart = 0;
	uint64_t lastAllocationBase = 0;
	do
	{
		bytesReturned = VirtualQueryEx (processHandle, (LPVOID) pageStart, &mbi, sizeof(mbi));
		baseRegion & actualBaseRegion = baseRegions.back ();

		if (mbi.State != MEM_FREE)
		{
			//printf ("BaseAddress %.16llx AllocationBase %.16llx RegionSize %.16llx \n", mbi.BaseAddress, mbi.AllocationBase, mbi.RegionSize);

			if ((uint64_t) mbi.AllocationBase != lastAllocationBase) // new baseRegion
			{
				baseRegion newBaseRegion;
				newBaseRegion.base = (uint64_t) mbi.AllocationBase;
				baseRegions.push_back (newBaseRegion);
			}
			memoryRegion newMemoryRegion;
			newMemoryRegion.start = (uint64_t) mbi.BaseAddress;
			newMemoryRegion.size = (uint64_t) mbi.RegionSize;

			setProtectStateType (mbi, &newMemoryRegion);
			baseRegions.back().memRegions.push_back(newMemoryRegion);
			
			lastAllocationBase = (uint64_t) mbi.AllocationBase;
		}

		pageStart += mbi.RegionSize;
	}
	while (bytesReturned);
}
void memoryMap::showMemoryMap (HANDLE stdoutHandle)
{
	printf ("|    Address     |      Size      |        Name        |  State | Type | Prot |\n");
	printf ("-------------------------------------------------------------------------------\n");
	for (const auto & i : baseRegions)
	{
		//printf ("Base %.16llx \n", i.base);
		for (const auto & j : i.memRegions)
		{
			printf ("|%.16llx|%.16llx|                    |%.8s|  %.3s | %.5s|\n", j.start, j.size, j.state.c_str(), j.type.c_str(), j.protection.c_str());
		}
	}
	printf ("-------------------------------------------------------------------------------\n");
}