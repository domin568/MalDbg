#pragma once

#include <windows.h>
#include <vector>
#include <map>
#include <memory>

#include "utils.h"
#include "structs.h"

struct section
{
	uint64_t address;
	uint64_t size;
	std::string name;
};

class PEparser 
{
	private:
	void * baseAddress;
	void * entryPoint;
	void * PEheaderAddr;

	HANDLE stdoutHandle;
	HANDLE processHandle;

	uint8_t ntHeaders [sizeof(IMAGE_NT_HEADERS64)];

	int wow64 = false;
	int nSections;
	bool virtualMode = false;
	uint64_t sectionsHeadersOffset;

	FILE * f;

	void * getPEstructureVirtual ();
	uint32_t getPEstructureFile ();
	
	void checkArchVirtual ();
	void checkArchFile ();

	void readPEheaderVirtual ();
	void readPEheaderFile ();

	std::vector<IMAGE_SECTION_HEADER> getSectionsVirtual ();
	std::vector<IMAGE_SECTION_HEADER> getSectionsFile ();
	
	bool isAddrInSection (uint64_t, IMAGE_SECTION_HEADER *);
	IMAGE_SECTION_HEADER getEntryPointSection ();

	uint8_t * readDataFromDirectory (uint32_t, uint64_t &, uint32_t &);
	uint64_t getPESizeInMemory ();
	uint8_t * getPEMemory ();
	
	public:
	PEparser (HANDLE, uint64_t); // in virtual memory
	PEparser (std::string); // exe file

	void * getEntryPoint (); 
	uint64_t getCoffSymbolTableOffset (); 
	uint32_t getCoffSymbolNumber (); 
	uint64_t getCoffExtendedNamesOffset ();
	std::vector <COFFentry> getCoffEntries ();
	std::unique_ptr<uint8_t []> getCoffExtendedNames ();
	uint64_t getSectionAddressForIndex (int);
	uint32_t getNumberOfSections ();

	std::string getSectionNameForAddress (uint64_t); 

	void showSections ();
	std::map <uint64_t, section> getPESections ();
	uint64_t fileOffsetToVirtualAddress (uint64_t); 
	std::vector <RUNTIME_FUNCTION> getPdataEntries ();

	void parseExportFunctionsVirtual ();
	std::map <std::string, std::vector<uint64_t> > getFunctionAddressesFromIAT ();
};