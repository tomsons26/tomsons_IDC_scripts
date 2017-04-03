//
//Function Symbol dump Script
//by tomsons26
//Writes only Function symbols to a runnable idc script\
//Way faster then the previous script and no alignment definition needed
//

#include <idc.idc>
#include "badnames.idc"

#define Script_Version "0.0.0.1"

static main() 
{
	auto Segment_Start, Segment_End;
	auto Path, Handle;
	auto IDB_Path, Input_Filename, Checksum;

	//Check if currently read segment has good start and end addresses
	Segment_Start = FirstSeg();
	Segment_End = SegEnd(Segment_Start);
	if (Segment_Start == BADADDR || Segment_End == BADADDR)
	{
		return;
	}

	//Show Save as dialog
	Path = AskFile(1, "*.idc", "Save idc script");
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
 
	fprintf(Handle,"//\n" "//Function Symbol Name Script V%s\n", Script_Version);

	//Get info
	IDB_Path = GetIdbPath();
	// Instead of full Path could get just filename, might be useful for public dumps.
	//Input_Filename = GetInputFile()
	Checksum = GetInputMD5();

	//Print db Path and MD5 as a comment for safety sake to confirm its the correct IDB
	fprintf(Handle,"//\n//IDB Path for this IDB was %s\n", IDB_Path);	
	//Message("//Filename for the binary was %s\n", Input_Filename );
	
	//Print Checksum definition
	fprintf(Handle,"\n#define Checksum \"%s\"\n\n", Checksum);

	//Print idc headers
	fprintf(Handle,"#include <idc.idc>\n\n""static main(void)\n");

	//Print symbol frame start
	fprintf(Handle,"{\n");
	
	//Print Checksum check function
	fprintf(Handle,"	if (GetInputMD5() != Checksum)\n	{\n");
	fprintf(Handle,"		Message(\"Checksum does not match current IDB!\\n\");\n");
	fprintf(Handle,"		return;\n	}\n");

	//Start dumping function symbol names
	Print_Symbol_Info(Handle);

	//Print symbol frame start
	fprintf(Handle,"}");

	//Close file
	fclose(Handle);
}

static Print_Symbol_Info(Handle)
{
	auto Symbol_Address, String;

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
				//If all good print it
				fprintf(Handle, "	MakeName (0x%X, \"%s\");\n", Symbol_Address, String);
			}
		}
		//Get next function address
		Symbol_Address = NextFunction(Symbol_Address);
	}
}