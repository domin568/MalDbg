#pragma once

#include <windows.h>
#include <vector>
#include <map>

#include <capstone/capstone.h>
#include "breakpoint.h"
#include "utils.h"
#include "symbolParse.h"

class disassembler
{
	private:
		csh handle;
		HANDLE stdoutHandle;
		uint64_t baseAddress;
		std::map <uint64_t, symbol> const * symbols;
		breakpoint * searchForBreakpoint (std::vector <breakpoint> & b, void * address);

	public:
		const uint32_t MAX_INSTRUCTION_LENGTH = 15;
		disassembler (uint64_t, std::map <uint64_t, symbol> const *);
		~disassembler ();
		void disasm (uint64_t, uint8_t *, uint32_t, uint32_t, std::vector <breakpoint> &);
};