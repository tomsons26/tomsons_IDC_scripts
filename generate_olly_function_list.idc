//
//Olly CSV Function Symbol dump Script
//by tomsons26
//Writes only Function symbols to a CSV compatible with CnCNet Olly tools
//

#include <idc.idc>
#include "badnames.idc"

#define Script_Version "0.0.0.1"

static main() 
{
	auto Segment_Start, Segment_End;
	auto Path, Handle;

	//Check if currently read segment has good start and end addresses
	Segment_Start = FirstSeg();
	Segment_End = SegEnd(Segment_Start);
	if (Segment_Start == BADADDR || Segment_End == BADADDR)
	{
		return;
	}

	//Show Save as dialog
	Path = AskFile(1, "*.csv", "Save CSV");
	if (Path == "")
	{
		return;
	}

	//Create Handle
	Handle = fopen(Path, "wb");
	if (!Handle)
	{
		return;
	}
 
	//Start dumping function symbol names
	Print_Symbol_Info(Handle);

	//Close file
	fclose(Handle);
}

static Print_Symbol_Info(Handle)
{
	auto Symbol_Address, String, Final_String, BaseAddress;
	
	//Get Base Address
	BaseAddress = FirstSeg() - 0x00001000;
	
	//Continue running as long as Symbol_Address is not a bad address
	while( Symbol_Address != BADADDR )
	{
		//Get Function name
		String = GetFunctionName(Symbol_Address);
		//Check if got the name
		if( String != 0 )
		{
			//If so check if its a bad name or not
			if (Check_For_Bad_Name(String) == 0)
			{
			Final_String = Demangle(String, INF_SHORT_DN);

			//If demangled result blank use original string
			if (Final_String == "")
			{
			Final_String = String;
			}
			//If all good print it
			//Format RVA,"label","comment"
			fprintf(Handle, "%08X,\"%s\",\"%s\")\n", (Symbol_Address - BaseAddress), Final_String, Final_String);
			}
		}
		//Get next function address
		Symbol_Address = NextFunction(Symbol_Address);
	}
}