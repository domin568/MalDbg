#include "symbolParse.h"

coffSymbolParser::coffSymbolParser ()
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
}
void coffSymbolParser::parseSymbols (std::vector <COFFentry> COFFTable)
{
	for (const auto & entry : COFFTable)
	{
		printf ("%-8s, VAL %.08x, SECTION NUMBER %.04x, SYMBOL TYPE %.04x STORAGE CLASS %.02x AUX %.02x\n", 
		entry.e.e_name, entry.e_value, entry.e_scnum, entry.e_type, entry.e_sclass, entry.e_numaux);
	}
}