#include "peParser.h"

PEparser::PEparser (HANDLE processHandle, uint64_t baseAddress)
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	this->processHandle = processHandle;
	this->baseAddress = (void *) baseAddress;

	PEheaderAddr = getPEstructure ();
	checkArch ();
	readPEheader ();

	//entryPoint = getEntryPoint ();
	
}
void  PEparser::readPEheader ()
{
	uint32_t size = (wow64 == 0 ? sizeof(IMAGE_NT_HEADERS64) : sizeof (IMAGE_NT_HEADERS32));
	if (!ReadProcessMemory (processHandle, (LPCVOID) PEheaderAddr, ntHeaders, size, NULL))
	{
		log ("Cannot read Image NT headers \n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
}
void PEparser::checkArch ()
{
	uint8_t machineType [2];
	if (!ReadProcessMemory (processHandle, (uint8_t *) PEheaderAddr + 4, machineType, 2, NULL))
	{
		log ("Cannot read PE header signature\n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
	if (!memcmp(machineType,"\x64\x86",2))
	{
		wow64 = false;
	}
	else if (!memcmp(machineType,"\x0c\x14",2))
	{
		wow64 = true;
	}
	else 
	{
		log ("File not supported, how did you start this process ???\n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
}
IMAGE_SECTION_HEADER * PEparser::getSections (int * nSections)
{
	uint32_t size = (wow64 == 0 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32));
	WORD numberOfSections;
	if (wow64)
	{
		numberOfSections = ( (IMAGE_NT_HEADERS32*) ntHeaders)->FileHeader.NumberOfSections;
	}
	else
	{
		numberOfSections = ( (IMAGE_NT_HEADERS64*) ntHeaders)->FileHeader.NumberOfSections;
	}
	uint64_t sectionsStartAddr =  (uint64_t) PEheaderAddr + size;

	*nSections = numberOfSections;

	IMAGE_SECTION_HEADER * sections = new IMAGE_SECTION_HEADER [numberOfSections];

	for (int i = 0 ; i < numberOfSections; i++)
	{
		if (!ReadProcessMemory (processHandle, (LPCVOID) sectionsStartAddr + (sizeof(IMAGE_SECTION_HEADER) * i), &sections[i], sizeof (IMAGE_SECTION_HEADER), NULL))
		{
			log ("Cannot read section from PE file\n", logType::ERR, stdoutHandle);
			throw std::exception ();
		}
	}
	return sections;
}
std::map <uint64_t, section> PEparser::getPESections ()
{
	std::map <uint64_t, section> toRet;
	int nSections;
	IMAGE_SECTION_HEADER * sections = getSections (&nSections);
	for (int i = 0 ; i < nSections; i++)
	{
		const char * a = (const char *) sections[i].Name; 
		std::string name (a);
		section s;
		s.address = sections[i].VirtualAddress + (uint64_t) baseAddress;

		s.size = sections[i].Misc.VirtualSize;
		if (s.size & 0xfff)
		{
			s.size += 0x1000;
			s.size &= 0xfffffffffffff000;
		}
		s.name = name;

		toRet[sections[i].VirtualAddress + (uint64_t) baseAddress] = s;
	}
	return toRet;
}
void * PEparser::getPEstructure ()
{
	IMAGE_DOS_HEADER * dosHeader = new IMAGE_DOS_HEADER;
	if (!ReadProcessMemory (processHandle, (LPCVOID) baseAddress, (uint8_t *) dosHeader, sizeof (IMAGE_DOS_HEADER), NULL))
	{
		log ("Cannot read DOS header of this executable\n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
	void * PEaddr = (void *)((uint64_t )baseAddress + (uint64_t) dosHeader->e_lfanew);
	delete dosHeader;
	return PEaddr;
}
bool PEparser::isAddrInSection (uint64_t addr, IMAGE_SECTION_HEADER * section)
{
	if (addr >= section->VirtualAddress + (uint64_t) baseAddress && addr < section->VirtualAddress + section->Misc.VirtualSize + (uint64_t) baseAddress)
	{
		return true;
	}
	return false;
}
IMAGE_SECTION_HEADER * PEparser::getEntryPointSection ()
{
	int nSections;
	IMAGE_SECTION_HEADER * sections = getSections (&nSections);
	for (int i = 0; i < nSections; i++)
	{
		if (isAddrInSection((uint64_t) entryPoint, &sections[i]))
		{
			return &sections[i];
		}
	}
	log ("Cannot get section within entrypoint, something very nasty \n", logType::ERR, stdoutHandle);
	throw std::exception ();
}
void * PEparser::getEntryPoint ()
{
	if (wow64)
	{
		return (void *) ( ( (IMAGE_NT_HEADERS32*) ntHeaders)->OptionalHeader.AddressOfEntryPoint + (uint64_t) baseAddress);
	}
	else 
	{
		return (void *) ( ( (IMAGE_NT_HEADERS64*) ntHeaders)->OptionalHeader.AddressOfEntryPoint + (uint64_t) baseAddress);
	}
}
void PEparser::showSections ()
{
	int nSections;
	IMAGE_SECTION_HEADER * sections = getSections (&nSections);
	for (int i = 0 ; i < nSections; i++)
	{
		printf ("%s --> %.16llx VIRT[%.16llx] RAW[%.16llx]\n", sections[i].Name, sections[i].VirtualAddress + (uint64_t) baseAddress, sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
	}
	delete sections;
}
