#pragma once

#include <windows.h>
#include "utils.h"
#include "peb.h"

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

	HANDLE stdoutHandle;
	HANDLE processHandle;

	uint8_t ntHeaders [sizeof(IMAGE_NT_HEADERS64)];

	int wow64 = false;
	int nSections;

	void * getPEstructure ();
	void * PEheaderAddr;
	
	IMAGE_SECTION_HEADER * getSections (int *);
	void readPEheader ();
	void checkArch ();
	bool isAddrInSection (uint64_t, IMAGE_SECTION_HEADER *);
	IMAGE_SECTION_HEADER * getEntryPointSection ();
	
	public:
	PEparser (HANDLE, uint64_t);
	void showSections ();
	void * getEntryPoint ();
	std::map <uint64_t, section> getPESections ();
};