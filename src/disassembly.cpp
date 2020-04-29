#include "disassembly.h"

disassembler::disassembler(uint64_t baseAddress, std::map <uint64_t, symbol> const * symbols)
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	this->baseAddress = baseAddress;
	this->symbols = symbols;

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
void disassembler::disasm (uint64_t address, uint8_t * codeBuffer, uint32_t codeSize, uint32_t numberOfInstructions, std::vector <breakpoint> & breakpoints)
{
	cs_insn *insn;
    size_t count;
    std::vector <breakpoint *> disassembledBreakpoints;

    count = cs_disasm (handle, codeBuffer, codeSize, (uint64_t)address, 0, &insn);
    if (count > 0)
    {
        for (int j = 0; j < (numberOfInstructions >= count ? count : numberOfInstructions); j++) // iterate over all instructions disassembled to find breakpoint locations
        {
            breakpoint * bp = searchForBreakpoint (breakpoints, (void *) insn[j].address);
            if (bp)
            {
                disassembledBreakpoints.push_back (bp); // even if breakpoint is not restored yet or it is hardware it is displayed
            }
            if (!strncmp (insn[j].mnemonic, "int3", 4) && bp ) // if breakpoint is set and there is 0xcc byte 
            {
                if (bp->getType() == breakpointType::SOFTWARE_TYPE) // user software breakpoint
                {
                    size_t int3Offset = insn[j].address - (uint64_t) address;
                    codeBuffer [int3Offset] = bp->getOriginalByte();
                    cs_free (insn, count);
                    count = cs_disasm (handle, codeBuffer, numberOfInstructions * 8 , (uint64_t) address, 0, &insn); // disassembly again
                }
            }
        }
        for (int j = 0 ; j < (numberOfInstructions >= count ? count : numberOfInstructions); j++)
        {
            // X86_REL_ADDR macro
            cs_detail *detail = insn[j].detail;
            for (int i = 0; i < 8; i++)
            {
                if (detail->groups[i] == 2 || detail->groups[i] == 1) // call or jump
                {
                    cs_x86_op *op = &(detail->x86.operands[0]);
                    if (op->type == X86_OP_IMM)
                    {
                        if (symbols->find(op->imm - baseAddress) != symbols->end())
                        {
                            std::string a = symbols->at(op->imm - baseAddress).name;
                            printf ("%s %i", a.c_str(), symbols->at(op->imm - baseAddress).sectionNumber);
                        }  
                    }
                }
            }
            bool breakpointShown = false;
            for (const auto & a : disassembledBreakpoints) // search for line with breakpoint
            {
                if ((void *) insn[j].address == a->getAddress() && a->getType() == breakpointType::SOFTWARE_TYPE && !a->getIsOneHit())
                {
                    printfColor ("0x%.16llx:\t%s\t\t%s\n", 12, stdoutHandle, insn[j].address, insn[j].mnemonic, insn[j].op_str); // breakpoint line spotted
                    breakpointShown = true;
                }
                else if ((void *) insn[j].address == a->getAddress() && a->getType() == breakpointType::HARDWARE_TYPE)
                {
                    printfColor ("0x%.16llx:\t%s\t\t%s\n", 9, stdoutHandle,  insn[j].address, insn[j].mnemonic, insn[j].op_str);
                    breakpointShown = true;
                }
            }
            if (!breakpointShown) // if line is not breakpoint print it normally
            {
                /*
                    for (int n = 0; n < detail->x86.op_count; n++) 
                    {
                        cs_x86_op *op = &(detail->x86.operands[n]);
                        switch(op->type) 
                        {
                            case X86_OP_REG:
                            printf("operands[%u].type: REG = %s\n", n, cs_reg_name(handle, op->reg));
                            break;
                            
                            case X86_OP_IMM:
                            printf("operands[%u].type: IMM = %.16llx\n", n, op->imm);
                            break;
                            
                            
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
                printf ("0x%.16llx:\t%s\t\t%s\n",insn[j].address, insn[j].mnemonic, insn[j].op_str);
            }
        }
        cs_free (insn, count);
    }
    else
    {
        log ("Cannot disassembly memory at %.16llx\n",logType::ERR, stdoutHandle,  address);
    }

}