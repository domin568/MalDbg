#pragma once

#include <vector>
#include <memory>

#include <windows.h>
#include "utils.h"
#include "peParser.h"
#include "structs.h"

enum symbolType
{
    FUNCTION_NAME = 0,
    NAME = 1
};

struct symbol
{
	std::string name;
	int sectionNumber;
	symbolType type;
};

class coffSymbolParser 
{
	private:
		HANDLE processHandle;
		HANDLE stdoutHandle;
	public:
		coffSymbolParser ();
		std::map <uint64_t, symbol> parseSymbols (std::vector <COFFentry>, std::unique_ptr<uint8_t []> &, uint64_t, PEparser &);
};
