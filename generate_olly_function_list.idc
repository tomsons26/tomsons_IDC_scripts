//
//Olly CSV Function Symbol dump Script
//by tomsons26
//Writes only Function symbols to a CSV compatible with CnCNet Olly tools
//

#include <idc.idc>

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

//Checks for names that shouldn't be printed
static Check_For_Bad_Name(String)
{
	auto s;

	if (String == "")
	{
		return 1;
	}

	s = substr(String, 0, 4);
	if (s == "sub_" ||
		s == "SEH_" ||
		s == "unk_" ||
		s == "loc_" ||
		s == "off_" ||
		s == "flt_" ||
		s == "dbl_" ||
		s == "asc_")
	{
		return 1;
	}

	s = substr(String, 0, 5);
	if (s == "byte_" ||
		s == "word_" ||
		s == "stru_")
	{
		return 1;
	}

	s = substr(String, 0, 6);
	if (s == "dword_" ||
		s == "__imp_" ||
		s == "j_sub_" ||
		s == "j_SEH_" ||
		s == "qword_")
	{
		return 1;
	}

	s = substr(String, 0, 7);
	if (s == "locret_" ||
		s == "__imp__")
	{
		return 1;
	}

	s = substr(String, 0, 8);
	if (s == "nullsub_" ||
		s == "j_nullsu" ||
		s == "xmmword_")
	{
		return 1;
	}

	s = substr(String, 0, 16);
	if (s == "unknown_libname_" ||
		s == "j_unknown_libnam" ||
		s == "__IMPORT_DESCRIP")
	{
		return 1;
	}

	return 0;
}