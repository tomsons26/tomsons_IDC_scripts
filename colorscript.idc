//
//Set Color script
//by tomsons26
//Sets assembly color to a chosen color for example for making chunks as decompiled

#include <idc.idc>

static main()
{
	auto Current,Selection_Start,Selection_End; 

	//Get the selection start and end address
	Selection_Start = SelStart(); 
	Selection_End	= SelEnd(); 
	
	//Check if the start and end addresses are valid
	if(Selection_End == BADADDR || Selection_Start== BADADDR)
	{
		Message("**Set Color Script Range Error**") ;
		return -1; 
	}

	//Sets the color for the range from Selection start to the end
	for (Current = Selection_Start; Current!=BADADDR; Current = NextHead(Current, Selection_End))
	{
		//Sets the color, format is address, type, and color in hex as 0xBBGGRR
		if (SetColor(Current,CIC_ITEM,0xEEFFF0)==0)
		{
			Message("**SetColor function Error**") ; 
		}
	}
	//Refreshes all disassembly views
	Refresh(); 
}