//
//Jump Function Define Script
//by tomsons26
//Defines jump functions from start to end address so you don't have to
//

#include <idc.idc>

#define Start_Address 0x00401000
#define End_Address 0x0041964B

static main(void)
{
	auto Symbol_Address = Start_Address;

	while(Symbol_Address!=End_Address)
	{
		Symbol_Address  = FindBinary(Symbol_Address, 3, "E9");
		
		MakeFunction(Symbol_Address,BADADDR);
		
		//Message("Function made at %08X\n", Symbol_Address);	
	}
}
