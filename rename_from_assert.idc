//
// Rename functions using Assert print strings script
// by tomsons26
//
// Searches for specified Assert line and then recurses back to the asm line that has the reference to the function name
// then renames the function to that string
// I made it modular sorta speak, in theory all you need to do is change the defines to adapt it to your executable, at least for x86
//

#include <idc.idc>

#define EXECUTABLESTART 0x00401000
#define ASSERT_CALL "[edx+64h]"
#define DISTANCETONAME 0x1D

//Wrapper for GetString to make the code easier to read
static Get_Name(address)
{
    return GetString(GetOperandValue(address, 0), -1, 0);
}

static main()
{
    auto Segment_End, Count, Failed, Address, Current_Address, Function_Start, Function_Name, ret;

    Segment_End = SegEnd(EXECUTABLESTART);
    Count = 0;
    Failed = 0;

    for ( Address = EXECUTABLESTART; Address < Segment_End; Address = Address + 4 ) {
		
		//Every few 0x10000 print where the scan is at currently
        if ( Address % 0x10000 == 0 ) Message("Scanning: %x/%x\n", Address, Segment_End);
		
        //Make sure the address we are checking is code so it doesn't get stuck for a long time at areas full of alignment bytes
        if ( isCode(GetFlags(Address)) ) {

            //Scan for the assert line
            if ( strstr(GetDisasm(Address), ASSERT_CALL) != -1 ) {
                Function_Name = 0;

                //Step back to the asm line that sets the function name for the assert to print
                Current_Address = Address - DISTANCETONAME;

                //Make sure we have no function name already and the Operand is indeed a reference to a string
                if ( Function_Name == 0 && strstr(GetOpnd(Current_Address, 0), "offset asc_") == 0 ) {
					
                    //Get the function name from the Operand Value
                    Function_Name = Get_Name(Current_Address);
                    Function_Start = GetFunctionAttr(Current_Address, FUNCATTR_START);
					
                    if ( Function_Start == 0xFFFFFFFF ) continue;

                    //Make sure the current function is named sub_ before renaming it
                    if ( strstr(GetFunctionName(Function_Start), "sub_") == 0 && strlen(GetFunctionName(Function_Start)) >= 10 ) {
						
                        //Create the function name format
                        Function_Name = form("%s", Function_Name);
						
						//Rename the function setting the name as public and replacing invalid chars with _
                        ret = MakeNameEx(Function_Start, Function_Name, SN_PUBLIC|SN_NOCHECK);
                        Message("Found name at %x and Renamed %x to %s\n", Current_Address, Function_Start, Function_Name);
						
						if (ret == 0) Failed = Failed + 1;
                    }
                }
            }
            Count = Count + 1;
        }
    }
    Message("Attempted to rename %d functions\nFailed to rename %d functions\n", Count, Failed);
}
