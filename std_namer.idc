//
// Names STD/STLPort templated functions
// by tomsons26

#include <idc.idc>
#include "find_helpers.idc"

static Do_Rename(ea, name_part1, name_part2, name_part3)
{
    auto new_name, cls;
    if (Is_Unamed_Function(ea)) {
        cls = form("TEMP_%X", ea);
        new_name = form("%s%s%s%s%s", name_part1, cls, name_part2, cls, name_part3);
        Rename_Function(GetFunctionAttr(ea, FUNCATTR_START), new_name);
    } else {
        Message("Function already named %s\n", ea, GetFunctionName(ea));
    }
}

// pattern matching method
static Map_From_Pattern(name_part1, name_part2, name_part3, pattern)
{
    auto ea;  

    for ( ea = FirstSeg(); ea != BADADDR;) {
        ea = FindBinary(ea, SEARCH_DOWN, pattern);
        if (ea == BADADDR) {
            break;
        }
        Do_Rename(ea, name_part1, name_part2, name_part3);
        ea = ea + 4;
    }
}

//xref matching method
static Rename_Xrefs_To(fun_name, name_part1, name_part2, name_part3)
{
    auto ref;
    auto loc = LocByName(fun_name);
    if (loc != BADADDR)
    {
        for (ref = RfirstB(loc); ref != BADADDR; ref = RnextB(loc,ref))
        {
            Do_Rename(ref, name_part1, name_part2, name_part3);
        }
    } else {
        Message("Can't find function with name %s!\nHave you named it!?\n", fun_name);
    }
}
static main()
{
    //deallocate
    //Map_From_Pattern(
    //"?deallocate@?$allocator@V",
    //"@@@_STL@@QBEXPAV",
    //"@@I@Z",
    //"55 8B EC 51 89 4D FC 83 7D 08 00 74 ? 8B 45 0C ? ? ? 50 8B 4D 08 51 E8 ? ? ? ? 83 C4 08 8B E5 5D C2 08");
    
    //Map_From_Pattern(
    //"?deallocate@?$allocator@V",
    //"@@@_STL@@QBEXPAV",
    //"@@I@Z",
    //"55 8B EC 51 89 4D FC 83 7D 08 00 74 ? 8B 45 0C ? ? 50 8B 4D 08 51 E8 ? ? ? ? 83 C4 08 8B E5 5D C2 08");
    
    //Map_From_Pattern(
    //"?deallocate@?$allocator@V",
    //"@@@_STL@@QBEXPAV",
    //"@@I@Z",
    //"55 8B EC 51 89 4D FC 83 7D 08 00 74 16 8B 45 0C 69 C0 ? ? 00 00 50 8B 4D 08 51 E8 ? ? ? ? 83 C4 08 8B E5 5D C2 08");
    
    //Map_From_Pattern(
    //"?deallocate@?$allocator@V",
    //"@@@_STL@@QBEXPAV",
    //"@@I@Z",
    //"55 8B EC 51 89 4D FC 83 7D 08 00 74 10 8B 45 0C 50 8B 4D 08 51 E8 ? ? ? ? 83 C4 08 8B E5 5D C2 08");
    
    //patterns is a shitty mightmare so lets try xrefs instead
    Rename_Xrefs_To("?deallocate@__new_alloc@_STL@@SAXPAXI@Z",
    "?deallocate@?$allocator@V",
    "@@@_STL@@QBEXPAV",
    "@@I@Z");
	
	Rename_Xrefs_To("?allocate@__new_alloc@_STL@@SAPAXI@Z",
    "?allocate@?$allocator@V",
    "@@@_STL@@QBEPAV",
    "@@IPBX@Z");
}