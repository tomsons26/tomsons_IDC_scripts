//
// Rename functions with hashes
// by tomsons26
//
// Searches for specified hash then renames the function to the specified name
// I made it modular sorta speak, in theory all you need to do is change the defines to adapt it to your executable, at least
// for x86
//

#include <idc.idc>

#define EXECUTABLESTART 0x00401000

static Check_Hash(address)
{
    auto hash;
    hash = GetOperandValue(address, 1);
    //didn't get a valid op val
    if (hash == -1) return 0;
    
    //check for these hashes
    if (hash == 0xDEFCA2F6) return "DefaultHotKeys";
    if (hash == 0x21BA45A7) return "ImageSequence";
    if (hash == 0x5080A5D8) return "MappableKey";
    if (hash == 0xA6E6BBA7) return "HotKeySlot";
    if (hash == 0x5F969146) return "MapMetaData";
    return 0;
    
}

static main()
{
    auto Segment_End, Renamed, Failed, Address, Function_Start, TypeName;

    Segment_End = SegEnd(EXECUTABLESTART);
    Renamed = 0;
    Failed = 0;
    Message("Starting Scan from 0x%08X to 0x%08X\n", Address, Segment_End);
    for (Address = EXECUTABLESTART; Address < Segment_End; Address = NextHead(Address, -1)) {
        // Every 0x20000 print where the scan is at currently
        if (Address % 0x20000 == 0)
            Message("Scanning: 0x%08X/0x%08X\n", Address, Segment_End);

        // reset any previous values
        TypeName = 0;
        Function_Start = -1;

        // Make sure the address we are checking is code so it doesn't get stuck for a long time at areas full of alignment
        // bytes
        if (isCode(GetFlags(Address))) {
            TypeName = Check_Hash(Address);
            if (TypeName != 0) {
                // Message("Found Type at 0x%08X - %s\n", Address, TypeName);
                // Make sure the current function is named sub_ before renaming it
                if (strstr(GetFunctionName(Address), "sub_") != -1) {
                    Function_Start = GetFunctionAttr(Address, FUNCATTR_START);
                    // Create the function name format
                    TypeName = form(
                        "%s%s%s", "??0?$TypeHandlerTemplate@U", TypeName, "@SageBinaryData@@@ResourceManager@@UAE_NH@Z");
                    if (MakeNameEx(Function_Start, TypeName, SN_PUBLIC | SN_NOCHECK | SN_NOWARN) != 0) {
                        Message("Found name at 0x%08X and Renamed 0x%08X to %s\n", Address, Function_Start, TypeName);
                        Renamed++;
                    } else {
                        Message("Can't rename 0x%08X to \"%s\" using assert line at 0x%08X\n",
                            Function_Start,
                            TypeName,
                            Address);
                        Failed++;
                    }
                }
            }
        }
    }
    Message("Renamed %d functions\nFailed to rename %d functions\n", Renamed, Failed);
}
