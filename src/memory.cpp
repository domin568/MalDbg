#include "memory.h"

typedef NTSTATUS (*pNtQueryInformationProcess) (HANDLE, DWORD, PVOID, ULONG, PULONG);

pNtQueryInformationProcess NtQueryInformationProcess()
{
    static pNtQueryInformationProcess fNtQueryInformationProcess = NULL;
    if (!fNtQueryInformationProcess)
    {
        HMODULE hNtdll = GetModuleHandle("ntdll.dll"); // loaded in every process not needed to load library
        fNtQueryInformationProcess = (pNtQueryInformationProcess) GetProcAddress(hNtdll, "NtQueryInformationProcess");
    }
    return fNtQueryInformationProcess;
}

std::string memoryProtection::toString ()
{
	return (read == 1 ? std::string("R") : std::string("-")) + (write == 1 ? std::string("W") : std::string("-")) + (execute == 1 ? std::string("X") : std::string("-")) + (copy == 1 ? std::string("C") : std::string("-")) + (guard == 1 ? std::string("G") : std::string("-"));
}
std::string memoryRegion::toString ()
{
	return name + " " + std::to_string (start) + " " + std::to_string (size) + " " + protection.toString() + " " + state + " " + type;
}

memoryMap::memoryMap (HANDLE processHandle, int is32bit) 
{
	this->processHandle = processHandle;
	this->is32bit = is32bit;
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
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

		region->protection = prot;
	}
	else if (mbi.State == MEM_RESERVE)
	{
		region->state = "RESERVED";
	}
}
void memoryMap::updateMemoryMap ()
{
	baseRegions.clear ();
	MEMORY_BASIC_INFORMATION mbi;

	size_t bytesReturned;
	uint64_t pageStart = 0;
	uint64_t lastAllocationBase = 0;

	std::vector <moduleData> modules = getModulesLoaded ();
	for (auto & module : modules)
	{
		PEparser parser (processHandle, module.VAaddress);
		module.sections = parser.getPESections();
	}
	do
	{
		bytesReturned = VirtualQueryEx (processHandle, (LPVOID) pageStart, &mbi, sizeof(mbi));

		if (mbi.State != MEM_FREE)
		{
			if ((uint64_t) mbi.AllocationBase != lastAllocationBase) // new baseRegion
			{
				baseRegion newBaseRegion;
				newBaseRegion.base = (uint64_t) mbi.AllocationBase;
				if (mbi.Type == MEM_IMAGE)
				{
					newBaseRegion.isIMG = true;
				}
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

	// now we have to join memory sections with their protections
	for (auto & baseRegion : baseRegions)
	{
		for (const auto & module : modules)
		{
			if (baseRegion.base == module.VAaddress)
			{
				std::vector <memoryRegion> regions;

				memoryRegion header = baseRegion.memRegions[0];
				header.name = module.name; // PWSTR to std::string
				baseRegion.name = module.name;
				regions.push_back (header);

				for ( auto & [key, val] : module.sections )
				{
					memoryRegion memRegion;

					memRegion.start = val.address;
					memRegion.protection = protectionForAddr (memRegion.start);
					memRegion.name = val.name;
					memRegion.size = val.size;
					memRegion.type = typeForAddr (memRegion.start);
					memRegion.state = stateForAddr (memRegion.start);
					regions.push_back (memRegion);
          		}
          		baseRegion.memRegions.clear();
          		baseRegion.memRegions = regions;
			}
		}
	}
}
std::vector <uint64_t> memoryMap::getModulesAddr ()
{
	std::vector <uint64_t> toRet;
	std::vector <moduleData> modules = getModulesLoaded ();

	for (auto i : modules)
	{
		toRet.push_back (i.VAaddress);
	}
	return toRet;
}
void memoryMap::showMemoryMap ()
{
	printf ("|    Address     |      Size      |        Name        |  State | Type | Prot |\n");
	printf ("-------------------------------------------------------------------------------\n");
	for (auto & i : baseRegions)
	{
		for (int j = 0; j < i.memRegions.size(); j++)
		{
			DWORD currentColor = getCurrentPromptColor (stdoutHandle);
			if (i.isIMG && j == 0)
			{
				currentColor = logType::WARNING;
			}
			else if (i.isIMG && j > 0)
			{
				currentColor = logType::INFO;
			}
			printfColor ("|%.16llx|%.16llx|", currentColor, stdoutHandle, i.memRegions[j].start, i.memRegions[j].size);
			centerTextColor (i.memRegions[j].name.c_str(), 20, currentColor, stdoutHandle);
			printfColor ("|%.8s|  %.3s ", currentColor, stdoutHandle, i.memRegions[j].state.c_str(),
			              i.memRegions[j].type.c_str());
			if (!strncmp (i.memRegions[j].protection.toString().c_str(), "RWX", 3))
			{
				currentColor = logType::ERR;
			}
			printfColor ("|%.5s|\n", currentColor, stdoutHandle, i.memRegions[j].protection.toString().c_str());
			
			//printf ("|%.16llx|%.16llx|", i.memRegions[j].start, i.memRegions[j].size);
			//centerText (j.name.c_str() ,20);
			//printf ("|%.8s|  %.3s | %.5s|\n", i.memRegions[j].state.c_str(), i.memRegions[j].type.c_str(), i.memRegions[j].protection.toString().c_str());
		}
	}
	printf ("-------------------------------------------------------------------------------\n");
}
memoryProtection memoryMap::protectionForAddr (uint64_t addr)
{
	for (const auto & i : baseRegions)
	{
		for (const auto & j : i.memRegions)
		{
			if (addr >= j.start && (uint64_t) addr < j.start + j.size)
			{
				return j.protection;
			}
		}
	}
}
std::string memoryMap::stateForAddr (uint64_t addr)
{
	for (const auto & i : baseRegions)
	{
		for (const auto & j : i.memRegions)
		{
			if (addr >= j.start && (uint64_t) addr < j.start + j.size)
			{
				return j.state;
			}
		}
	}
}
std::string memoryMap::typeForAddr (uint64_t addr)
{
	for (const auto & i : baseRegions)
	{
		for (const auto & j : i.memRegions)
		{
			if (addr >= j.start && (uint64_t) addr < j.start + j.size)
			{
				return j.type;
			}
		}
	}
}
DWORD memoryMap::memoryProtectionToDWORD (memoryProtection prot) // kinda noobish
{
	DWORD toRet = 0;
	if (!prot.execute && !prot.read && !prot.write && !prot.copy)
	{
		toRet = PAGE_NOACCESS;
	}
	else if (prot.execute && !prot.read && !prot.write && !prot.copy)
	{
		toRet = PAGE_EXECUTE;
	}
	else if (prot.execute && prot.read && !prot.write && !prot.copy)
	{
		toRet = PAGE_EXECUTE_READ;
	}
	else if (prot.execute && prot.read && prot.write && !prot.copy)
	{
		toRet = PAGE_EXECUTE_READWRITE;
	}
	else if (prot.execute && prot.read && prot.write && prot.copy)
	{
		toRet = PAGE_EXECUTE_WRITECOPY;
	}
	else if (!prot.execute && prot.read && !prot.write && !prot.copy)
	{
		toRet = PAGE_READONLY;
	}
	else if (!prot.execute && prot.read && prot.write && prot.copy)
	{
		toRet = PAGE_WRITECOPY;
	}
	if (prot.guard)
	{
		toRet |= PAGE_GUARD;
	}
	return toRet;
}
void memoryMap::setProtection (uint64_t address, uint64_t size, memoryProtection prot)
{
	DWORD protFlags = memoryProtectionToDWORD (prot);
	DWORD oldProtFlags;
	if (!VirtualProtectEx (processHandle, (void *) address, size, protFlags ,&oldProtFlags))
	{
		DWORD err = GetLastError();
		log ("Cannot change protection on page with address %.16llx err %.08x\n",logType::ERR, stdoutHandle, address, err);
	}
}
void * memoryMap::getPEBaddr () // just for 64 bit env
{
    PROCESS_BASIC_INFORMATION64 processInfo {};
    NtQueryInformationProcess () (processHandle, 0, &processInfo, sizeof (processInfo), nullptr); // 0 - ProcessBasicInformation
    return (void *) processInfo.PebBaseAddress;
}
std::vector <moduleData> memoryMap::getModulesLoaded ()
{
    std::vector <moduleData> modules;
    DWORD procId = GetProcessId (processHandle);

   	DWORD snapshotFlag = (is32bit == 1 ? TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE : TH32CS_SNAPMODULE);

   	HANDLE hSnapshot = CreateToolhelp32Snapshot(snapshotFlag, procId);
    MODULEENTRY32 lpme;
    bool firstStatus = Module32First(hSnapshot, &lpme);
    if (!firstStatus)
    {
    	log ("Module32First error when getting modules loaded",logType::ERR, stdoutHandle);
    }
    moduleData m;
    m.VAaddress = (uint64_t) lpme.modBaseAddr;
    m.name = std::string(lpme.szModule);
    modules.push_back (m);
    while (Module32Next (hSnapshot, &lpme))
    {
    	m.VAaddress = (uint64_t) lpme.modBaseAddr;
       	m.name = std::string (lpme.szModule);
       	modules.push_back (m);
    }  
    return modules;
}
std::string memoryMap::getSectionNameForAddress (uint64_t addr)
{
	for (const auto & i : baseRegions)
	{
		for (const auto & j : i.memRegions)
		{
			if (addr >= j.start && addr < j.start + j.size)
			{
				return j.name;
			}
		}
	}
	return "?";
}
std::string memoryMap::getImageNameForAddress (uint64_t addr)
{
	for (const auto & i : baseRegions)
	{
		for (const auto & j : i.memRegions)
		{
			if (addr >= j.start && addr < j.start + j.size)
			{
				return i.name;
			}
		}
	}
	return "?";
}

// ******************************************************************************************************************************************

memoryHelper::memoryHelper (HANDLE processHandle, HANDLE stdoutHandle)
{
	this->processHandle = processHandle;
	this->stdoutHandle = stdoutHandle;
}
bool memoryHelper::printHexdump (void * address, uint32_t size)
{
	uint8_t * b = new uint8_t [size];
	SIZE_T bytesRead;
	uint64_t currentAddress = (uint64_t) address; 
	if (!ReadProcessMemory (processHandle, (LPVOID) address, b, size, &bytesRead))
	{
		log ("Cannot read memory for hexdump\n", logType::ERR, stdoutHandle);
		return false;
	}

	uint32_t bytesLeft = bytesRead;

	for (int i = 0 ; i < bytesRead; i+=hexdumpWidth)
	{
		printf ("%.16llx | ", currentAddress+i);
		for (int j = 0 ; j < (bytesLeft < hexdumpWidth ? bytesLeft : hexdumpWidth); j++)
		{
			printf ("%.02x ", (int) b[i+j]);
		}
		if (bytesLeft < hexdumpWidth)
		{
			for (int k = 0; k < hexdumpWidth - bytesLeft; k++)
			{
				printf ("   ");
			}
		}
		printf ("| ");
		for (int j = 0 ; j < (bytesLeft < hexdumpWidth ? bytesLeft : hexdumpWidth); j++)
		{
			printf ("%c",b[i+j]);
		}
		printf ("\n");
		bytesLeft -= hexdumpWidth;
	}
	delete [] b;
}
bool memoryHelper::writeIntAt (uint64_t value, void * addr, uint32_t size)
{
	if (!WriteProcessMemory (processHandle, (LPVOID) addr, &value, size, NULL))
	{
		log ("Cannot write memory at specified address %.16llx\n", logType::ERR, stdoutHandle, addr);
		return false;
	}
	return true;
}
