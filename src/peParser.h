#pragma once

#include <windows.h>
#include "utils.h"
#include "peb.h"
#include <vector>
#include "symbolParse.h"

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
	
	public:
	PEparser (HANDLE, uint64_t); // in virtual memory
	PEparser (std::string); // exe file

	void * getEntryPoint (); // OK
	uint64_t getCoffSymbolTableOffset (); // OK
	uint32_t getCoffSymbolNumber (); // OK
	std::vector <COFFentry> getCoffEntries ();
	uint32_t getNumberOfSections (); // ok

	void showSections ();
	std::map <uint64_t, section> getPESections ();
	uint64_t fileOffsetToVirtualAddress (uint64_t); 
};