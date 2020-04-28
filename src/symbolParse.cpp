#include "symbolParse.h"

coffSymbolParser::coffSymbolParser ()
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
}
std::map <uint64_t, symbol> coffSymbolParser::parseSymbols (
	std::vector <COFFentry> COFFTable,
	std::unique_ptr<uint8_t []> & extendedNames,
	uint64_t extendedCoffNamesOffset,
	PEparser & pe)
{	
	std::map <uint64_t, symbol> toRet; // RVA
	for (const auto & entry : COFFTable)
	{	
		// types 0x20, 0x02, 0x3, 0x0
		int sectionIdx = entry.e_scnum-1;
		if (sectionIdx < 0 || sectionIdx > pe.getNumberOfSections())
		{
			continue;
		}
		uint64_t RVA = pe.getSectionAddressForIndex(sectionIdx);
		uint32_t nameSize = strlen (entry.e.e_name);

		if (entry.e.e.e_zeroes != 0  && entry.e_scnum != 0) // function to 8 chars
		{
			toRet [RVA + entry.e_value] = 
			{
				std::string (entry.e.e_name, (nameSize > 8 ? 8 : nameSize)),
				entry.e_scnum,
				(entry.e_type == 0x20 ? symbolType::FUNCTION_NAME : symbolType::NAME)
			};
			//printf ("FUNC %.8s\n", entry.e.e_name);
		}
		else if (entry.e.e.e_zeroes == 0 && entry.e.e.e_offset != 0  && entry.e_scnum != 0) // function with extended name
		{
			toRet [RVA + entry.e_value] =
			{ 
				std::string ((const char *)&extendedNames[entry.e.e.e_offset]),
				entry.e_scnum,
				(entry.e_type == 0x20 ? symbolType::FUNCTION_NAME : symbolType::NAME)
			};
			//printf ("FUNC %s\n", &extendedNames[entry.e.e.e_offset]);		
		}
	}
	return toRet;
}