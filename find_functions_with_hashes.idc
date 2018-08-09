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

// ida arrays can hold two types at the same time
// there's also a fancier HashArray but dunno how to use it
static Set_Array_Entry(array, index, hash, name)
{
    SetArrayLong(array, index, hash);
    SetArrayString(array, index, name);
    // hack to increment the index
    return index + 1;
}

// build a array we can later use
static Create_Name_Array()
{
    auto array, index;
    array = CreateArray("pairarray");

    index = Set_Array_Entry(array, index, 0xDEFCA2F6, "DefaultHotKeys");
    index = Set_Array_Entry(array, index, 0x21BA45A7, "ImageSequence");
    index = Set_Array_Entry(array, index, 0x5080A5D8, "MappableKey");
    index = Set_Array_Entry(array, index, 0xA6E6BBA7, "HotKeySlot");
    index = Set_Array_Entry(array, index, 0x5F969146, "MapMetaData");
    // add new ones here cloning the line above

    Message("index is %d\n", index);
}

// scan code for the hash

// can also use
// disasm = GetDisasm(address);
// if (strstr(disasm, hash) != hash) {
static Scan_For_Hash(address)
{
    auto i, array;
    array = GetArrayId("pairarray");
    for (i = GetFirstIndex(AR_LONG, array); i != BADADDR; i = GetNextIndex(AR_LONG, array, i)) {
        if (GetOperandValue(address, 1) == GetArrayElement(AR_LONG, array, i)) {
            return GetArrayElement(AR_STR, array, i);
        }
    }
    return "NONE";
}

static main()
{
    auto Segment_End, Renamed, Failed, Address, Function_Start, TypeName;

    Segment_End = SegEnd(EXECUTABLESTART);
    Renamed = 0;
    Failed = 0;
    Create_Name_Array();
    for (Address = EXECUTABLESTART; Address < Segment_End; Address = Address + 1) {
        // Every 0x10000 print where the scan is at currently
        if (Address % 0x10000 == 0)
            Message("Scanning: 0x%08X/0x%08X\n", Address, Segment_End);

        // reset any previous values
        TypeName = 0;
        Function_Start = -1;

        // Make sure the address we are checking is code so it doesn't get stuck for a long time at areas full of alignment
        // bytes
        if (isCode(GetFlags(Address))) {
            TypeName = Scan_For_Hash(Address);
            if (TypeName != "NONE") {
                Function_Start = GetFunctionAttr(Address, FUNCATTR_START);

                // Message("Found Type at 0x%08X - %s\n", Address, TypeName);
                // Make sure the current function is named sub_ before renaming it
                if (Function_Start != -1 && strstr(GetFunctionName(Function_Start), "sub_") != -1) {
                    // Create the function name format
                    TypeName = form(
                        "%s%s%s", "??0?$TypeHandlerTemplate@U", TypeName, "@SageBinaryData@@@ResourceManager@@UAE_NH@Z");
                    if (MakeNameEx(Function_Start, TypeName, SN_PUBLIC | SN_NOCHECK | SN_NOWARN) != 0) {
                        Message("Found name at 0x%08X and Renamed 0x%08X to %s\n", Address, Function_Start, TypeName);
                        Renamed = Renamed + 1;
                    } else {
                        Message("Can't rename 0x%08X to \"%s\" using assert line at 0x%08X\n",
                            Function_Start,
                            TypeName,
                            Address);
                        Failed = Failed + 1;
                    }
                }
            }
        }
    }
    Message("Renamed %d functions\nFailed to rename %d functions\n", Renamed, Failed);
}
