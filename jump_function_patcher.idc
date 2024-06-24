garbage

//
//Jump Function Define Script
//by tomsons26
//Defines jump functions from start to end address so you don't have to
//

#include <idc.idc>

#define Start_Address 0x10001000
#define End_Address 0x10001019

static main(void)
{
	auto Symbol_Address = Start_Address;

	while(Symbol_Address <= End_Address)
	{
		Symbol_Address = FindBinary(Symbol_Address, 3, "E9");
		
    
        auto base = Dword(Symbol_Address + 1);
        auto xref = RfirstB(Symbol_Address);
        while( xref != BADADDR )
        {
            Message("Loc %x ref from %x patched to %x\n", Symbol_Address, xref, Symbol_Address - base);

            PatchDword(xref+1, Symbol_Address - base);
            DelCodeXref(xref, Symbol_Address, 0 );

            xref = RnextB(Symbol_Address, xref);
        }
        
        
		//MakeFunction(Symbol_Address,BADADDR);
		
		//Message("Function made at %08X\n", Symbol_Address);	
	}
}
