#include "disassembly.h"

disassembler::disassembler(uint64_t baseAddress, std::map <uint64_t, symbol> const * symbols)
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	this->baseAddress = baseAddress;
	this->symbols = symbols;

	defaultColor = getCurrentPromptColor (stdoutHandle);

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
    	log ("Cannot initialize capstone disassemble\n",logType::ERR, stdoutHandle);
        return;
    }
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
    {
    	log ("Cannot set detail disassembly option in capstone disassembler\n",logType::ERR, stdoutHandle);
        return;
    }
}
disassembler::~disassembler()
{
	cs_close (&handle);
}
breakpoint * disassembler::searchForBreakpoint (std::vector <breakpoint> & b, void * address)
{
    for (auto & i : b)
    {
        if (i.getAddress() == address)
        {
            return &i;
        }
    }
    return nullptr;
}
void disassembler::changeBreakpointsToOriginal (
	std::vector <breakpoint *> & disassembledBreakpoints,
	std::vector <breakpoint> & breakpoints,
	cs_insn ** insn,
	uint8_t * codeBuffer,
	uint64_t address,
	uint32_t codeSize,
	uint32_t numberOfInstructions,
	size_t count
	 )
{
	for (int j = 0; j < (numberOfInstructions >= count ? count : numberOfInstructions); j++) // iterate over all instructions disassembled to find breakpoint locations
    {
        breakpoint * bp = searchForBreakpoint (breakpoints, (void *) (*insn)[j].address);
        if (bp)
        {
            disassembledBreakpoints.push_back (bp); // even if breakpoint is not restored yet or it is hardware it is displayed
        }
        if (!strncmp ((*insn)[j].mnemonic, "int3", 4) && bp ) // if breakpoint is set and there is 0xcc byte 
        {
            if (bp->getType() == breakpointType::SOFTWARE_TYPE) // user software breakpoint
            {
                size_t int3Offset = (*insn)[j].address - (uint64_t) address;
                codeBuffer [int3Offset] = bp->getOriginalByte();
                cs_free (*insn, count);
                count = cs_disasm (handle, codeBuffer, codeSize , (uint64_t) address, 0, insn); // disassembly again
            }
        }
    }
}
instructionType disassembler::getInstructionType (cs_insn insn, cs_detail * detail)
{
	instructionType type;

	for (int i = 0 ; i < 8; i++)
	{
		if (detail->groups[i] == x86_insn_group::X86_GRP_INVALID)
		{
			type.X86_GRP_INVALID = true;
		}
		else if (detail->groups[i] == x86_insn_group::X86_GRP_JUMP)
		{
			type.X86_GRP_JUMP = true;
		}
		else if (detail->groups[i] == x86_insn_group::X86_GRP_CALL)
		{
			type.X86_GRP_CALL = true;
		}
		else if (detail->groups[i] == x86_insn_group::X86_GRP_RET)
		{
			type.X86_GRP_RET = true;
		}
		else if (detail->groups[i] == x86_insn_group::X86_GRP_INT)
		{
			type.X86_GRP_INT = true;
		}
		else if (detail->groups[i] == x86_insn_group::X86_GRP_IRET)
		{
			type.X86_GRP_IRET = true;
		}
		else if (detail->groups[i] == x86_insn_group::X86_GRP_PRIVILEGE)
		{
			type.X86_GRP_PRIVILEGE = true;
		}
		else if (detail->groups[i] == x86_insn_group::X86_GRP_BRANCH_RELATIVE)
		{
			type.X86_GRP_BRANCH_RELATIVE = true;
		}
	}
	return type;
}
void disassembler::parseInstruction (cs_insn insn, disassemblyLineInfo & lineInfo)
{
	if (symbols->find(insn.address - baseAddress) != symbols->end())
    {
        std::string a = symbols->at(insn.address - baseAddress).name;
        centerTextColor (a.c_str(), 60, 15, stdoutHandle);
        printf ("\n\n");
    }
	cs_detail *detail = insn.detail;
	instructionType type = getInstructionType (insn, detail);

	lineInfo.address.val = insn.address;
	lineInfo.address.color = defaultColor;
	lineInfo.mnemonic.str = std::string(insn.mnemonic);
	lineInfo.mnemonic.color = defaultColor;

    if (type.X86_GRP_CALL || type.X86_GRP_JUMP && detail->x86.op_count == 1) // call or jump with imm or memory (call puts)
    {
        cs_x86_op *op = &(detail->x86.operands[0]);

        if (op->type == X86_OP_IMM)
        {
            if (symbols->find(op->imm - baseAddress) != symbols->end())
            {
                std::string a = symbols->at(op->imm - baseAddress).name;
                lineInfo.op.str = a;
                lineInfo.op.color = 15;
                return;
            }  
        }
        if (op->type == X86_OP_MEM)
        {
        	uint64_t relativeAddress = X86_REL_ADDR (insn);
        	if (symbols->find(relativeAddress - baseAddress) != symbols->end())
            {
                std::string a = symbols->at(relativeAddress - baseAddress).name;
                lineInfo.op.str = a;
                lineInfo.op.color = 15;
                return;
            }  
        }
    }
    else if (detail->x86.op_count == 2 && detail->x86.operands[0].type == X86_OP_MEM && detail->x86.operands[0].mem.base != NULL) // mnemonic relative_memory_symbol, reg/imm
    {
    	if (!strncmp(cs_reg_name(handle, detail->x86.operands[0].mem.base), "rip", 3))
    	{
    		uint64_t relativeAddress = X86_REL_ADDR (insn);
    		if (symbols->find(relativeAddress - baseAddress) != symbols->end())
            {
                std::string op1 = symbols->at(relativeAddress - baseAddress).name;
                std::string op2 = "";
                if (detail->x86.operands[1].type == X86_OP_REG)
            	{
            		op2 = cs_reg_name(handle, detail->x86.operands[1].reg);
            	}
            	else if (detail->x86.operands[1].type == X86_OP_IMM)
            	{
            		op2 = std::to_string(detail->x86.operands[1].imm);
            	}
            	lineInfo.op.str = op1 + " <" + intToHex(relativeAddress) + ">, " + op2;
            	lineInfo.op.color = 15;
                return;
            }
    	}
    }
    else if (detail->x86.op_count == 2 && detail->x86.operands[1].type == X86_OP_MEM && detail->x86.operands[1].mem.base != NULL) // mnemonic reg, relative_memory_symbol
    {
		if (!strncmp(cs_reg_name(handle, detail->x86.operands[1].mem.base), "rip", 3))
    	{
			uint64_t relativeAddress = X86_REL_ADDR (insn);
    		if (symbols->find(relativeAddress - baseAddress) != symbols->end())
            {
                std::string op2 = symbols->at(relativeAddress - baseAddress).name;
                std::string op1 = "";
            	op1 = cs_reg_name(handle, detail->x86.operands[0].reg);
       			lineInfo.op.str = op1 + ", " + op2 + " <" + intToHex(relativeAddress) + ">";
       			lineInfo.op.color = 15;
                return;
            }
    	}	
    }
    	/*
        for (int n = 0; n < detail->x86.op_count; n++) 
    	{
        	cs_x86_op *op = &(detail->x86.operands[n]);
        	switch(op->type) 
        	{
            	case X86_OP_REG:
            	{
            		printf("operands[%u].type: REG = %s\n", n, cs_reg_name(handle, op->reg));
            		break;
            	}
            	case X86_OP_IMM:
            	{
            		printf("operands[%u].type: IMM = %.16llx\n", n, op->imm);
            		break;
            	}
            	case X86_OP_MEM:
            	{
                	if (op->mem.base != X86_OP_INVALID)
               		printf("operands[%u].mem.base: REG = %s\n", n, cs_reg_name(handle, op->mem.base));
                	if (op->mem.index != X86_OP_INVALID)
                	printf("operands[%u].mem.index: REG = %s\n", n, cs_reg_name(handle, op->mem.index));
                	if (op->mem.disp != 0)
                	printf("operands[%u].mem.disp: 0x%x\n", n, op->mem.disp);
                	break;
            	}
            
        	}
    	}
    	*/
    lineInfo.op.str = std::string (insn.op_str); // id any symbol applies then leave it as it is
    lineInfo.op.color = defaultColor;
}
void disassembler::printLine (std::vector <breakpoint *> & disassembledBreakpoints, disassemblyLineInfo & line)
{
	bool breakpointShown = false;
    for (const auto & a : disassembledBreakpoints) // search for line with breakpoint
    {
        if ((void *) line.address.val == a->getAddress() && a->getType() == breakpointType::SOFTWARE_TYPE && !a->getIsOneHit())
        {
            printfColor ("0x%llx:\t%s\t\t%s\n", 12, stdoutHandle, line.address.val, line.mnemonic.str.c_str(), line.op.str.c_str()); // breakpoint line spotted
            breakpointShown = true;
        }
        else if ((void *) line.address.val == a->getAddress() && a->getType() == breakpointType::HARDWARE_TYPE)
        {
            printfColor ("0x%llx:\t%s\t\t%s\n", 9, stdoutHandle, line.address.val, line.mnemonic.str.c_str(), line.op.str.c_str());
            breakpointShown = true;
        }
    }
    if (!breakpointShown) // if line is not breakpoint print it normally
    {
        printfColor ("0x%llx:", line.address.color, stdoutHandle, line.address.val);
        printfColor ("\t%s", line.mnemonic.color, stdoutHandle, line.mnemonic.str.c_str());
        printfColor ("\t\t%s\n", line.op.color, stdoutHandle, line.op.str.c_str());
        //printf ("0x%.16llx:\t%s\t\t%s\n", line.address.val, line.mnemonic.str.c_str(), line.op.str.c_str());
    }
}

void disassembler::disasm (uint64_t address, uint8_t * codeBuffer, uint32_t codeSize, uint32_t numberOfInstructions, std::vector <breakpoint> & breakpoints)
{
	cs_insn * insn;
    size_t count;
    std::vector <breakpoint *> disassembledBreakpoints;

    count = cs_disasm (handle, codeBuffer, codeSize, (uint64_t)address, 0, &insn);
    if (count > 0)
    {
    	changeBreakpointsToOriginal (
    		disassembledBreakpoints,
    		breakpoints,
    		&insn,
    		codeBuffer,
    		address,
    		codeSize,
    		numberOfInstructions,
    		count);

        for (int j = 0 ; j < (numberOfInstructions >= count ? count : numberOfInstructions); j++) // main print loop
        {
            // X86_REL_ADDR macro

            disassemblyLineInfo line;
            parseInstruction (insn[j], line);
            printLine (disassembledBreakpoints, line);
        }
        cs_free (insn, count);
    }
    else
    {
        log ("Cannot disassembly memory at %.16llx\n",logType::ERR, stdoutHandle,  address);
    }

}