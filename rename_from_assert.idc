//
// Rename functions using Assert print strings script
// by tomsons26
//
// Searches for specified Assert line and then recurses back to the asm line that has the reference to the function name
// then renames the function to that string
// I made it modular sorta speak, in theory all you need to do is change the defines to adapt it to your executable, at least
// for x86
//

#include <idc.idc>

#define EXECUTABLESTART 0x00401000

// Wrapper for GetString to make the code easier to read
// Gets name from pointer to a string
static Get_Name(address)
{
    return GetString(GetOperandValue(address, 0), -1, 0);
}

// define your checks for assert/print lines here
static Scan_For_Line(address)
{
    auto disasm;
    disasm = GetDisasm(address);
    if (strstr(disasm, "[edx+64h]") != -1) {
        return 0x1D;
    }
    if (strstr(disasm, "[edx+6Ch]") != -1) {
        return 0x1D;
    }
    if (strstr(disasm, "print_9EA930") != -1) {
        return 0x5;
    }
    return -1;
}

static main()
{
    auto Segment_End, Renamed, Failed, Address, Current_Address, Function_Start, Function_Name, distancetoname;

    Segment_End = SegEnd(EXECUTABLESTART);
    Renamed = 0;
    Failed = 0;

    for (Address = EXECUTABLESTART; Address < Segment_End; Address = Address + 1) {
        // Every 0x10000 print where the scan is at currently
        if (Address % 0x10000 == 0)
            Message("Scanning: 0x%08X/0x%08X\n", Address, Segment_End);

        //reset any previous values
        Function_Name = 0;
        distancetoname = -1;
        Function_Start = -1;

        // Make sure the address we are checking is code so it doesn't get stuck for a long time at areas full of alignment
        // bytes
        if (isCode(GetFlags(Address))) {
            // Scan for the assert line
            distancetoname = Scan_For_Line(Address);
            if (distancetoname != -1) {
                // Step back to the asm line that sets the function name for the assert to print
                Current_Address = Address - distancetoname;

                // Make sure we have no function name already and the Operand is indeed a reference to a string
                if (strstr(GetOpnd(Current_Address, 0), "asc_") != -1) {
                    // Get the function name from the Operand Value
                    Function_Name = Get_Name(Current_Address);
                    Function_Start = GetFunctionAttr(Current_Address, FUNCATTR_START);

                    // Message("Found name at 0x%08X - %s\n", Current_Address, Function_Name);
                    if (Function_Start != -1) {
                        // Make sure the current function is named sub_ before renaming it
                        if (strstr(GetFunctionName(Address), "sub_") != -1) {
                            // Create the function name format
                            Function_Name = form("%s", Function_Name);

                            // Rename the function setting the name as public and replacing invalid chars with _
                            if (MakeNameEx(Function_Start, Function_Name, SN_PUBLIC | SN_NOCHECK | SN_NOWARN) != 0) {
                                Message("Found name at 0x%08X and Renamed 0x%08X to %s\n",
                                    Current_Address,
                                    Function_Start,
                                    Function_Name);
                                Renamed = Renamed + 1;
                            } else {
                                Message("Can't rename 0x%08X to \"%s\" using assert line at 0x%08X\n",
                                    Function_Start,
                                    Function_Name,
                                    Current_Address);
                                Failed = Failed + 1;
                            }
                            
                        }
                    } else {
                        Message("Could not get Function Start of Function at 0x%08X\nThis should not happen!\n",
                            Current_Address);
                    }
                    
                }
            }
        }
    }
    Message("Renamed %d functions\nFailed to rename %d functions\n", Renamed, Failed);
}
