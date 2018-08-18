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
#include "find_helpers.idc"

#define EXECUTABLESTART 0x00401000

// define your checks for assert/print lines here
static Scan_For_Line(address)
{
    auto disasm;
    disasm = GetDisasm(address);
    if (String_Is_Present(disasm, "[edx+64h]")) {
        return 0x1D;
    }
    if (String_Is_Present(disasm, "[edx+6Ch]")) {
        return 0x1D;
    }
    if (String_Is_Present(disasm, "print_9EA930")) {
        return 0x5;
    }
    return -1;
}

static main()
{
    auto segment_end, renamed, failed, address, current_address, function_start, new_name, distancetoname;

    segment_end = SegEnd(EXECUTABLESTART);
    renamed = 0;
    failed = 0;
    Message("Starting Scan from 0x%08X to 0x%08X\n", address, segment_end);
    for (address = EXECUTABLESTART; address < segment_end; address = NextHead(address, -1)) {
        // Every 0x20000 print where the scan is at currently
        if (address % 0x20000 == 0) {
            Message("Scanning: 0x%08X/0x%08X\n", address, segment_end);
        }
        // reset any previous values
        new_name = 0;
        distancetoname = -1;
        function_start = -1;

        // Make sure the address we are checking is code so it doesn't get stuck for a long time at areas full of alignment
        // bytes
        if (isCode(GetFlags(address))) {
            // Scan for the assert line
            distancetoname = Scan_For_Line(address);
            if (distancetoname != -1) {
                // Step back to the asm line that sets the function name for the assert to print
                current_address = address - distancetoname;
                // Make sure we have no function name already and the Operand is indeed a reference to a string
                if (Is_String_Pointer(current_address)) {
                    new_name = Get_Name(current_address);
                    // Message("Found name at 0x%08X - %s\n", current_address, new_name);
                    // Make sure the current function is named sub_ before renaming it
                    if (new_name != 0 && Is_Unamed_Function(address)) {
                        function_start = GetFunctionAttr(address, FUNCATTR_START);
                        // Create the function name format
                        new_name = form("%s", new_name);

                        if (Rename_Function(function_start, new_name)) {
                            Message("Found name at 0x%08X and renamed 0x%08X to %s\n", address, function_start, new_name);
                            renamed++;
                        } else {
                            Message("Can't rename 0x%08X to \"%s\" using assert line at 0x%08X\n", function_start, new_name, address);
                            failed++;
                        }
                    }
                }
            }
        }
    }
    Message("Renamed %d functions\nFailed to rename %d functions\n", renamed, failed);
}
