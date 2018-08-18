//
// Rename functions with hashes
// by tomsons26
//
// Searches for specified hash then renames the function to the specified name
// I made it modular sorta speak, in theory all you need to do is change the defines to adapt it to your executable, at least
// for x86
//

#include <idc.idc>
#include "find_helpers.idc"

#define EXECUTABLESTART 0x00401000

static Scan_For_Hash(address)
{
    auto hash;
    hash = GetOperandValue(address, 1);
    // didn't get a valid op val
    if (hash == -1)
        return 0;

    // check for these hashes
    if (hash == 0xDEFCA2F6)
        return "DefaultHotKeys";
    if (hash == 0x21BA45A7)
        return "ImageSequence";
    if (hash == 0x5080A5D8)
        return "MappableKey";
    if (hash == 0xA6E6BBA7)
        return "HotKeySlot";
    if (hash == 0x5F969146)
        return "MapMetaData";

    // no hash matched
    return 0;
}

static main()
{
    auto segment_end, renamed, failed, address, function_start, new_name;

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

        function_start = -1;

        // Make sure the address we are checking is code so it doesn't get stuck for a long time at areas full of alignment
        // bytes
        if (isCode(GetFlags(address))) {
            // Scan for the hash
            new_name = Scan_For_Hash(address);
            // Message("Found Type at 0x%08X - %s\n", address, new_name);
            // Make sure the current function is named sub_ before renaming it
            if (new_name != 0 && Is_Unamed_Function(address)) {
                function_start = GetFunctionAttr(address, FUNCATTR_START);
                // Create the function name format
                new_name =
                    form("%s%s%s", "??0?$TypeHandlerTemplate@U", new_name, "@SageBinaryData@@@ResourceManager@@UAE_NH@Z");
                if (Rename_Function(function_start, new_name)) {
                    Message("Found name at 0x%08X and renamed 0x%08X to %s\n", address, function_start, new_name);
                    renamed++;
                } else {
                    Message("Can't rename 0x%08X to \"%s\" Hash found at 0x%08X\n", function_start, new_name, address);
                    failed++;
                }
            }
        }
    }

    Message("Renamed %d functions\nFailed to rename %d functions\n", renamed, failed);
}
