#pragma once

#include <windows.h>
#include <vector>
#include <map>

#include <capstone/capstone.h>
#include "breakpoint.h"
#include "utils.h"
#include "symbolParse.h"
#include "structs.h"

struct instructionType
{
	bool X86_GRP_INVALID = 0;

	// all jump instructions (conditional+direct+indirect jumps)
	bool X86_GRP_JUMP = 0;

	// all call instructions
	bool X86_GRP_CALL = 0;

	// all return instructions
	bool X86_GRP_RET = 0;

	// all interrupt instructions (int+syscall)
	bool X86_GRP_INT = 0;

	// all interrupt return instructions
	bool X86_GRP_IRET = 0;

	// all privileged instructions
	bool X86_GRP_PRIVILEGE = 0;

	// all relative branching instructions
	bool X86_GRP_BRANCH_RELATIVE = 0; 
};

struct disassemblyLineInfo
{
	struct
	{
		uint64_t val = 0xbeefc0de;
		DWORD color = 0;
	} address;
	struct
	{
		std::string str = "?";
		DWORD color = 0;
	} mnemonic;
	struct
	{
		std::string str = "";
		std::string op1 = "";
		std::string op2 = "";
		DWORD color = 0;
	} op;
};

class disassembler
{
	private:
		csh handle;
		HANDLE stdoutHandle;
		uint64_t baseAddress;
		DWORD defaultColor;
		std::map <uint64_t, symbol> const * symbols;
		std::vector <function> const * functionNames;

		breakpoint * searchForBreakpoint (std::vector <breakpoint> & b, void * address);
		std::string getFunctionNameStartForAddress (uint64_t address);
		std::string getFunctionNameEndForAddress (uint64_t address);

		void changeBreakpointsToOriginal (
			std::vector <breakpoint *> &,
			std::vector <breakpoint> &,
			cs_insn **,
			uint8_t *,
			uint64_t,
			uint32_t,
			uint32_t,
			size_t 
	 	);
	 	void printLine (std::vector <breakpoint *> &, disassemblyLineInfo &);
	 	void parseInstruction (cs_insn, disassemblyLineInfo &);
	 	instructionType getInstructionType (cs_insn, cs_detail *);
	 	void parseOperands ();
	public:
		const uint32_t MAX_INSTRUCTION_LENGTH = 15;
		disassembler (uint64_t, std::map <uint64_t, symbol> const *, std::vector <function> const *);
		~disassembler ();
		void disasm (uint64_t, uint8_t *, uint32_t, uint32_t, std::vector <breakpoint> &);
};