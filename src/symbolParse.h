#pragma once
#pragma pack(push)
#pragma pack(1)

#include <windows.h>
#include "utils.h"
#include <vector>

typedef struct 
{
  union 
  {
    char e_name[8];
    struct 
    {
      unsigned long e_zeroes;
      unsigned long e_offset;
    } e;
  } e;
  unsigned long e_value;
  short e_scnum;
  unsigned short e_type;
  unsigned char e_sclass;
  unsigned char e_numaux;
} COFFentry;

#pragma pack(pop)

class coffSymbolParser 
{
	private:
		HANDLE processHandle;
		HANDLE stdoutHandle;
	public:
		coffSymbolParser ();
		void parseSymbols (std::vector <COFFentry>);
};
