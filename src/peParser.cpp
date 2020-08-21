#include "peParser.h"

PEparser::PEparser (HANDLE processHandle, uint64_t baseAddress) // IN MEMORY
{
	virtualMode = true;
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	this->processHandle = processHandle;
	this->baseAddress = (void *) baseAddress;

	PEheaderAddr = getPEstructureVirtual ();
	checkArchVirtual ();
	readPEheaderVirtual ();	
}
PEparser::PEparser (std::string exePath) // ON DISK
{
	virtualMode = false;
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	f = fopen (exePath.c_str(), "rb");
	if (!f)
	{
		log ("Cannot open PE file from path %s \n", logType::ERR, stdoutHandle, exePath.c_str());
		throw std::exception ();
	}
	PEheaderAddr = (void *) getPEstructureFile ();
	checkArchFile ();
	readPEheaderFile ();	
}

/* GET PE STRUCTURE */

uint32_t PEparser::getPEstructureFile ()
{
	fseek (f, 0, 0);
	IMAGE_DOS_HEADER * dosHeader = new IMAGE_DOS_HEADER;
	size_t ret = fread (dosHeader, sizeof (IMAGE_DOS_HEADER), 1, f);
	if (ret != 1) // one element of IMAGE_DOS_HEADER
	{
		log ("Cannot read DOS header of executable\n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
	delete dosHeader;
	return dosHeader->e_lfanew;
}
void * PEparser::getPEstructureVirtual ()
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

/* END  GET PE STRUCTURE */

/* CHECK ARCH */

void PEparser::checkArchVirtual ()
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

void PEparser::checkArchFile ()
{
	fseek (f, (uint64_t) PEheaderAddr, 0); // move file to PE header offset 
	fseek (f, 4, 1); // move file ptr 4 bytes forward
	uint8_t machineType [2];
	if ( fread (machineType, 1, 2, f) != 2 )
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
		log ("File not supported, you are not gonna debug this program\n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
	fseek (f, -6, 1); // go to PE header again
}

/* END CHECK ARCH */

/* READ PE HEADER */

void  PEparser::readPEheaderVirtual ()
{
	uint32_t size = (wow64 == 0 ? sizeof(IMAGE_NT_HEADERS64) : sizeof (IMAGE_NT_HEADERS32));
	if (!ReadProcessMemory (processHandle, (LPCVOID) PEheaderAddr, ntHeaders, size, NULL))
	{
		log ("Cannot read Image NT headers \n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
}
void PEparser::readPEheaderFile ()
{
	fseek (f, (uint64_t) PEheaderAddr, 0);
	uint32_t size = (wow64 == 0 ? sizeof(IMAGE_NT_HEADERS64) : sizeof (IMAGE_NT_HEADERS32));
	if (fread (ntHeaders, 1, size, f) != size)
	{
		log ("Cannot read Image NT headers \n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
	if (wow64)
	{
		baseAddress = (void *)((IMAGE_NT_HEADERS32*) ntHeaders)->OptionalHeader.ImageBase;
	}
	else 
	{
		baseAddress = (void *) ((IMAGE_NT_HEADERS64*) ntHeaders)->OptionalHeader.ImageBase;
	}
	sectionsHeadersOffset = ftell (f);
}

/* END READ PE HEADER */

/* GET SECTIONS */

std::vector<IMAGE_SECTION_HEADER> PEparser::getSectionsVirtual ()
{
	uint32_t size = (wow64 == 0 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32));
	WORD numberOfSections = getNumberOfSections();
	uint64_t sectionsStartAddr =  (uint64_t) PEheaderAddr + size;

	IMAGE_SECTION_HEADER * sections = new IMAGE_SECTION_HEADER [numberOfSections];

	for (int i = 0 ; i < numberOfSections; i++)
	{
		if (!ReadProcessMemory (processHandle, (LPCVOID) sectionsStartAddr + (sizeof(IMAGE_SECTION_HEADER) * i), &sections[i], sizeof (IMAGE_SECTION_HEADER), NULL))
		{
			log ("Cannot read section from PE module\n", logType::ERR, stdoutHandle);
			throw std::exception ();
		}	
	}
	std::vector <IMAGE_SECTION_HEADER> toRet (sections, sections + numberOfSections);
	delete [] sections;
	return toRet;
}

std::vector<IMAGE_SECTION_HEADER> PEparser::getSectionsFile ()
{
	fseek (f, sectionsHeadersOffset, 0);
	std::vector <IMAGE_SECTION_HEADER> toRet;

	uint32_t size = (wow64 == 0 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32));
	WORD numberOfSections = getNumberOfSections();
	uint64_t sectionsStartAddr = (uint64_t) PEheaderAddr + size;

	IMAGE_SECTION_HEADER * sections = new IMAGE_SECTION_HEADER [numberOfSections];

	if (fread (sections, sizeof (IMAGE_SECTION_HEADER), numberOfSections, f) != numberOfSections)
	{
		log ("Cannot read section headers from PE file\n", logType::ERR, stdoutHandle);
		throw std::exception ();	
	}
	for (int i = 0 ; i < numberOfSections; i++)
	{
		toRet.push_back (sections[i]);
	}
	delete [] sections;
	return toRet;
}

/* END GET SECTIONS */

uint32_t PEparser::getNumberOfSections ()
{
	if (wow64)
	{
		return ( (IMAGE_NT_HEADERS32*) ntHeaders)->FileHeader.NumberOfSections;
	}
	else
	{
		return ( (IMAGE_NT_HEADERS64*) ntHeaders)->FileHeader.NumberOfSections;
	}
}

uint64_t PEparser::getCoffSymbolTableOffset ()
{
	if (wow64)
	{
		return ((IMAGE_NT_HEADERS32*) ntHeaders)->FileHeader.PointerToSymbolTable;
	}
	else 
	{
		return ((IMAGE_NT_HEADERS64*) ntHeaders)->FileHeader.PointerToSymbolTable;
	}
}
uint32_t PEparser::getCoffSymbolNumber ()
{
	if (wow64)
	{
		return ((IMAGE_NT_HEADERS32*) ntHeaders)->FileHeader.NumberOfSymbols;
	}
	else 
	{
		return ((IMAGE_NT_HEADERS64*) ntHeaders)->FileHeader.NumberOfSymbols;
	}
}

uint64_t PEparser::fileOffsetToVirtualAddress (uint64_t fileOffset)
{
	std::vector<IMAGE_SECTION_HEADER> sections = (virtualMode == 1 ? getSectionsVirtual () : getSectionsFile ());
	for (int i = 0 ; i < sections.size(); i++)
	{
		if (fileOffset>= sections[i].PointerToRawData && fileOffset < (sections[i].PointerToRawData + sections[i].SizeOfRawData))
		{
			uint64_t virtualAddress = (fileOffset - sections[i].PointerToRawData) + (uint64_t) baseAddress + sections[i].VirtualAddress;
			return virtualAddress;
		}
	}
}
std::map <uint64_t, section> PEparser::getPESections ()
{
	std::map <uint64_t, section> toRet;

	std::vector<IMAGE_SECTION_HEADER> sections = (virtualMode == 1 ? getSectionsVirtual () : getSectionsFile ());
	for (int i = 0 ; i < sections.size(); i++)
	{
		const char * a = (const char *) sections[i].Name; 
		uint32_t size = strlen (a);
		std::string name (a, (size > 8 ? 8 : size));
		section s;
		s.address = sections[i].VirtualAddress + (uint64_t) baseAddress;

		s.size = alignMemoryPageSize(sections[i].Misc.VirtualSize);

		s.name = name;

		toRet[sections[i].VirtualAddress + (uint64_t) baseAddress] = s;
	}
	return toRet;
}
bool PEparser::isAddrInSection (uint64_t addr, IMAGE_SECTION_HEADER * section)
{
	if (addr >= section->VirtualAddress + (uint64_t) baseAddress && addr < section->VirtualAddress + section->Misc.VirtualSize + (uint64_t) baseAddress)
	{
		return true;
	}
	return false;
}
IMAGE_SECTION_HEADER PEparser::getEntryPointSection ()
{
	std::vector<IMAGE_SECTION_HEADER> sections = (virtualMode == 1 ? getSectionsVirtual () : getSectionsFile ());
	for (int i = 0; i < sections.size(); i++)
	{
		if (isAddrInSection((uint64_t) entryPoint, &sections[i]))
		{
			return sections[i];
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
	std::vector<IMAGE_SECTION_HEADER> sections = (virtualMode == 1 ? getSectionsVirtual () : getSectionsFile ());
	for (int i = 0 ; i < sections.size(); i++)
	{
		printf ("%s --> %.16llx VIRT[%.16llx] RAW[%.16llx]\n", sections[i].Name, sections[i].VirtualAddress + (uint64_t) baseAddress, sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
	}
}
std::vector <COFFentry> PEparser::getCoffEntries ()
{
	if (virtualMode)
	{
		log ("You cannot read COFF symbols table within virtual memory\n", logType::ERR, stdoutHandle);
		throw std::exception();
	}
	fseek (f,getCoffSymbolTableOffset(),0);
	uint32_t quantinity = getCoffSymbolNumber();
	COFFentry * entires = new COFFentry [quantinity];
	if (fread(entires, sizeof (COFFentry), quantinity, f) != quantinity)
	{
		log ("Couldnt read COFF symbol table from file\n", logType::ERR, stdoutHandle);
		throw std::exception();
	}

	std::vector <COFFentry> toRet (entires, entires + quantinity);
	delete [] entires;
	return toRet;
}
uint64_t PEparser::getCoffExtendedNamesOffset ()
{
	uint64_t symbolsOffset = getCoffSymbolTableOffset();
	uint64_t symbolsSize = sizeof (COFFentry) * getCoffSymbolNumber ();
	return symbolsOffset + symbolsSize;
}
std::unique_ptr<uint8_t []> PEparser::getCoffExtendedNames ()
{
	uint64_t extendedNamesOffset = getCoffExtendedNamesOffset ();
	fseek (f, 0 , 2);
	uint64_t imageSize = ftell (f);
	fseek (f, extendedNamesOffset, 0);
	uint64_t toRead = imageSize - extendedNamesOffset; // we suppose that extended strings are rest of PE file

	auto extendedNamesBuff =std::make_unique<uint8_t []>(toRead); 
	if (fread (extendedNamesBuff.get(), 1, toRead, f) != toRead)
	{
		log ("Couldnt read COFF extended symbol names from file\n", logType::ERR, stdoutHandle);
		throw std::exception();
	}
	return extendedNamesBuff;
}
uint64_t PEparser::getSectionAddressForIndex (int idx)
{
	std::vector<IMAGE_SECTION_HEADER> sections = (virtualMode == 1 ? getSectionsVirtual() : getSectionsFile () );
	if (idx < 0 && idx >= sections.size())
	{
		log ("Couldnt get section nr %i\n", logType::ERR, stdoutHandle, idx);
		throw std::exception();
	}
	return sections[idx].VirtualAddress;
}
std::string PEparser::getSectionNameForAddress (uint64_t addr) // RVA for file, VA for module
{
	std::vector<IMAGE_SECTION_HEADER> sections = (virtualMode == 1 ? getSectionsVirtual() : getSectionsFile());
	for (int i = 0 ; i < sections.size() ; i++)
	{
		if (addr >= sections[i].VirtualAddress && addr < sections[i].VirtualAddress + alignMemoryPageSize(sections[i].Misc.VirtualSize))
		{
			uint32_t nameSize = strlen ((const char *)sections[i].Name);
			return std::string ( (const char *) sections[i].Name, (nameSize > 8 ? 8 : nameSize) );
		}
	}
	return "?";
}
std::vector <RUNTIME_FUNCTION> PEparser::getPdataEntries ()
{
	uint64_t addrToRead = 0;
	uint64_t size = 0;
	std::vector<IMAGE_SECTION_HEADER> sections = (virtualMode == 1 ? getSectionsVirtual () : getSectionsFile ());
	for (const auto & section : sections)
	{
		if (!strncmp ( (const char *) section.Name, ".pdata\x00\x00", 8))
		{
			size = section.SizeOfRawData;
			if (virtualMode)
			{
				addrToRead = (uint64_t) baseAddress + section.VirtualAddress;
			}
			else
			{
				addrToRead = section.PointerToRawData;
			}
		}
	}

	std::vector <RUNTIME_FUNCTION> pdataEntries ( (size / sizeof(RUNTIME_FUNCTION)) + sizeof(RUNTIME_FUNCTION) ); // because /3 is truncating result

	if (virtualMode)
	{
		if (!ReadProcessMemory (processHandle, (LPCVOID) addrToRead, (uint8_t *) pdataEntries.data(), size, NULL))
		{
			log ("Cannot read .pdata contents from module to get functions start and end addresses\n", logType::ERR, stdoutHandle);
			throw std::exception ();
		}
	}
	else
	{
		fseek (f, addrToRead ,0);
		if (fread (pdataEntries.data(), 1, size, f) != size)
		{
			log ("Cannot read .pdata contents from file to get functions start and end addresses\n", logType::ERR, stdoutHandle);
			throw std::exception ();
		}
	}
	return pdataEntries;
}
uint8_t * PEparser::readDataFromDirectory (uint32_t index, uint64_t & address, uint32_t & size)
{
	uint32_t directoryCount = ((IMAGE_NT_HEADERS64 *) ntHeaders)->OptionalHeader.NumberOfRvaAndSizes;
	if (index < 0 && index < directoryCount)
	{
		log ("Directory index invalid \n", logType::ERR, stdoutHandle);
		return NULL;
	}

	IMAGE_DATA_DIRECTORY dataDirectory = ((IMAGE_NT_HEADERS64 *) ntHeaders)->OptionalHeader.DataDirectory[index];
	if (dataDirectory.VirtualAddress == 0)
	{
		log ("Directory nr %i is not used \n", logType::ERR, stdoutHandle, index);
		return NULL; // PE has no import table ???
	}

	address = (uint64_t) baseAddress + dataDirectory.VirtualAddress;
	size = dataDirectory.Size;

	uint8_t * data = new uint8_t [size];

	if (!ReadProcessMemory (processHandle, (LPCVOID) address, data, size, NULL ))
	{
		log ("Cannot read Import Data\n", logType::ERR, stdoutHandle);
		return nullptr;
	}
	return data;
}
uint8_t * PEparser::getPEMemory ()
{
	if (!virtualMode)
	{
		log ("Cannot get PE memory from file \n", logType::UNKNOWN_EVENT, stdoutHandle);
		return nullptr;
	}
	uint64_t PEsize = getPESizeInMemory();
	uint8_t * PE = new uint8_t [PEsize];
	if (!ReadProcessMemory (processHandle, (LPCVOID) baseAddress, PE, PEsize, NULL ))
	{
		log ("Cannot read whole PE memory \n", logType::ERR, stdoutHandle);
		return nullptr;
	}
	return PE;
}
uint64_t PEparser::getPESizeInMemory ()
{
	if (!virtualMode)
	{
		return 0;
	}
	uint64_t toRet = ((IMAGE_NT_HEADERS64 *) ntHeaders)->OptionalHeader.SectionAlignment; // for first page of memory (headers)
	std::vector<IMAGE_SECTION_HEADER> sections = getSectionsVirtual ();
	for (const auto & i : sections)
	{
		toRet += alignMemoryPageSize(i.Misc.VirtualSize);
	}
	return toRet;
}
std::map <std::string, std::vector<uint64_t> > PEparser::getFunctionAddressesFromIAT ()
{
	std::map <std::string, std::vector<uint64_t> > toRet;

	if (!virtualMode) 
	{
		log ("Cannot parse import names from file \n", logType::UNKNOWN_EVENT, stdoutHandle);
		return toRet; 
	}
	uint8_t * PEmemory = getPEMemory ();
	if (PEmemory == nullptr)
	{
		return toRet;
	}

	uint64_t address;
	uint32_t size;
	uint8_t * importData = readDataFromDirectory (IMAGE_DIRECTORY_ENTRY_IMPORT, address, size);
	if (importData == NULL)
	{
		return toRet;
	}

	IMAGE_IMPORT_DESCRIPTOR * dllImported = (IMAGE_IMPORT_DESCRIPTOR *) importData;

	for (int i = 0; dllImported[i].Name != 0; i++)
	{
		uint32_t nameOffset = dllImported[i].Name;
		const char * moduleName = (const char *) (PEmemory + nameOffset);
		std::string moduleNameStr (moduleName);

		uint32_t IAToffset = dllImported[i].FirstThunk;
		uint64_t * IATpointer = (uint64_t *) (IAToffset + (uint64_t) PEmemory);

		for (int j = 0; IATpointer[j] != 0; j++)
		{
			toRet[moduleNameStr].push_back (IATpointer[j]);
		}
	}

	delete [] importData;
	delete [] PEmemory;
	return toRet;
}
std::map <uint64_t, std::string> PEparser::parseExportFunctionsVirtual ()
{
	std::map <uint64_t, std::string> toRet;
	if (!virtualMode) 
	{
		log ("Cannot parse export names from file \n", logType::UNKNOWN_EVENT, stdoutHandle);
		return toRet; 
	}
	uint64_t address;
	uint32_t size;
	uint8_t * exportData = readDataFromDirectory (IMAGE_DIRECTORY_ENTRY_EXPORT, address, size);
	if (exportData == NULL)
	{
		return toRet;
	}

	uint32_t functionNumber = ((IMAGE_EXPORT_DIRECTORY *)exportData)->NumberOfFunctions;
	uint32_t nameNumber = ((IMAGE_EXPORT_DIRECTORY *)exportData)->NumberOfNames;

	uint32_t functionAddressesOffset = ((IMAGE_EXPORT_DIRECTORY *)exportData)->AddressOfFunctions - (address - (uint64_t) baseAddress);
	uint32_t functionNamesOffset = ((IMAGE_EXPORT_DIRECTORY *)exportData)->AddressOfNames - (address - (uint64_t) baseAddress);
	uint32_t functionOrdinalsOffset = ((IMAGE_EXPORT_DIRECTORY *)exportData)->AddressOfNameOrdinals - (address - (uint64_t) baseAddress);
	
	int i = functionAddressesOffset;
	int j = functionNamesOffset;
	int k = functionOrdinalsOffset;
	uint32_t base = ((IMAGE_EXPORT_DIRECTORY *)exportData)->Base;
	int l = ((IMAGE_EXPORT_DIRECTORY *)exportData)->Base;

	uint32_t functionAddressesEndOffset = (functionNumber * sizeof (uint32_t) + functionAddressesOffset);

	for (;i < functionAddressesEndOffset ; i += sizeof (uint32_t))
	{
		bool isForwared = false;
		uint64_t addr = *((uint32_t *)(exportData + i)) + (uint64_t) baseAddress;

		// if func pointer points into export data then it is forwarded

		uint32_t nameOffset = (*((uint32_t *)(exportData + j)) - (address - (uint64_t) baseAddress));
		char * name = (char *)((uint32_t) nameOffset + (uint64_t) exportData);
		uint16_t ordinalToName = *((uint32_t *)(exportData + k));

		if ( (addr - (uint64_t) baseAddress) >= (address - (uint64_t) baseAddress) &&
			 (addr - (uint64_t) baseAddress) < (address + size - (uint64_t) baseAddress)) 
		{
			isForwared = true;
			//printf ("Ordinal [%i] forwarded to %s \n", ordinalToName + base, (char *) addr );
			// TODOOOOOOOOOOOOOOOOOOOOOOOOO
			toRet[addr] = ""; //std::string ( (char *) addr ); 
			// TODOOOOOOOOOOOOOOOOOOOOOOOOO segfault when normal string
		}
		toRet[addr] = ((ordinalToName + base) == l ? std::string(name) : "Ordinal Only");
		//printf ("%.16llx --> %s ordinal [%i] \n", addr, ((ordinalToName + base) == l ? name : "Ordinal Only"), l);
		if (ordinalToName + base == l)
		{
			j+= sizeof (uint32_t);
			k+= sizeof (uint16_t);
		}
		l++;
	}
	delete [] exportData;
	return toRet;
}