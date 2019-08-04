//CCN64 ROM Helper
//by tomsons26
//EU ROM
//Run this script at the start of a Segment struct

#include <idc.idc>

#define ROM_OFFSET 0x7FFFF400
#define CARTROM_OFFSET 0xB0000000

static main()
{
    Message("Segment Name      : %s\n", GetString(Dword(here), -1, 0));
    Message("ROM Start         : 0x%X\n", Dword(here+4));
    Message("ROM End           : 0x%X\n", Dword(here+4+4));
    Message("RAM Start         : 0x%X\n", Dword(here+4+4+4));
    Message("RAM End           : 0x%X\n", Dword(here+4+4+4+4));
    Message("Static Init1      : 0x%X\n", Dword(here+4+4+4+4+4));
    Message("Static Init2      : 0x%X\n", Dword(here+4+4+4+4+4+4));
    Message("Callback          : 0x%X\n\n", Dword(here+4+4+4+4+4+4+4));
    
    Message("ROM Start In File : 0x%X\n", Dword(here+4) - CARTROM_OFFSET);
    Message("ROM End In File   : 0x%X\n\n", Dword(here+4+4) - CARTROM_OFFSET);
    
    Message("Printing Info For Segment Creation\n");
    auto name;
    name = form("%sSeg", GetString(Dword(here), -1, 0));
    Message("%s\n", name);
    Message("Seg Start: 0x%X\n", Dword(here+4) - CARTROM_OFFSET + ROM_OFFSET);
    Message("Seg End  : 0x%X\n\n", Dword(here+4+4) - CARTROM_OFFSET + ROM_OFFSET);
    
    Message("Printing Info For MIPS Memory Mapping\n");
    Message("From    : 0x%X\n", Dword(here+4+4+4));
    Message("To      : 0x%X\n", Dword(here+4) - CARTROM_OFFSET + ROM_OFFSET);
    Message("Size    : 0x%X\n\n", (Dword(here+4+4) - CARTROM_OFFSET) - (Dword(here+4) - CARTROM_OFFSET));
}