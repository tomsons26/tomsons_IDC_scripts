//
//Symbol dump Script
//by tomsons26
//Writes symbols to a runnable idc script
//

//PROBABLY_TODO
//hhmmmm

#include <idc.idc>
#include "badnames.idc"

#define Script_Version "0.58.0"

//Binary alignment thats typically between functions
#define Alignment 4

static main() 
{
	auto Just_Functions, SpecificString, Filter;
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

	//Ask should only function names be written excluding data
	Just_Functions = AskYN(0, "Write only function names?");

	//If got -1(Cancel) stop execution
	if(Just_Functions == -1)
	{
		return;
	}

	//Show Save as dialog

	Filter = AskYN(0, "Write only symbols with a specific string?");

	//If got -1(Cancel) stop execution
	if(Filter == -1)
	{
		return;
	}

    SpecificString = "";
    if (Filter){
        SpecificString = AskStr("", "Type In string to filter.\nCase Sensitive!\nLeave black for all");
    }

	//Show Save as dialog
	Path = AskFile(1, "*.idc", "Save idc script");
	if (Path == "")
	{
		return;
	}

	Handle = fopen(Path, "wb");
	if (!Handle)
	{
		return;
	}
 
	fprintf(Handle,"//\n" "//Symbol Name Script V%s\n", Script_Version);
	fprintf(Handle,"//\n//Alignment set in script was %d dwords\n", Alignment);


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



	//Start dumping symbol names
	Print_Symbol_Info(Handle, Just_Functions, SpecificString);


	//Print symbol frame start
	fprintf(Handle,"}");


	//Close file
	fclose(Handle);
}

static String_Is_Present(check, string)
{
    if (strstr(check, string) != -1) {
        return 1;
    }
    return 0;
}

static Print_Symbol_Info(Handle, Is_Just_Functions, SpecificString)
{
	auto Segment_Start, Segment_End;
	auto Symbol_Address, Item_Flags, String;
    auto process;

	do
	{
		Segment_Start = NextSeg(Segment_Start);
		Segment_End = SegEnd(Segment_Start);
	}
	while (Segment_Start != BADADDR && Segment_End != BADADDR);

	Segment_Start = FirstSeg();
	Segment_End = SegEnd(Segment_Start);
	do
	{
		Symbol_Address = Segment_Start;
		while (Symbol_Address < Segment_End)
		{
			String = GetTrueNameEx(BADADDR, Symbol_Address);
            process = 1;
            if (SpecificString != "") {
                process = String_Is_Present(String, SpecificString);
            }
            
			if (process && Check_For_Bad_Name(String) == 0)
			{
				Item_Flags = GetFlags(Symbol_Address);
				if (!Is_Just_Functions || (Item_Flags & FF_CODE) == FF_CODE)
				{
					fprintf(Handle, "	MakeName (0x%X, \"%s\");\n", Symbol_Address, String);
				}
			}

			//Check for valid symbols within defined Alignment dword boundries
			//4 bytes is typically the alignment before functions
			//Extend if needed for binary
			Symbol_Address = Symbol_Address + Alignment;
		}

		Segment_Start = NextSeg(Segment_Start);
		Segment_End = SegEnd(Segment_Start);
	}
	//Continue running as long as neither Segment_Start and Segment_End are bad addresses
	while (Segment_Start != BADADDR && Segment_End != BADADDR);
}