//
// Reads array for check var function and names the stack vars
// by tomsons26
// currently only for MSVC _RTC_CheckStackVars but maybe can be adapted for any other compilers
#include "idc.idc"

static Read_CheckVar_Array(address)
{
    auto count, pointer, addr;

    //seek back to get pointer for function
    addr = Dword(address - 4);
    
    //get count of entries
    count = Dword(addr);
    
    
    auto start = GetFunctionAttr(address, FUNCATTR_START);
    
    Message("=== Stack Vars for 0x%x with %d entries :\n", start, count);

    //go to pointer
    pointer = Dword(addr + 4);
    
    
    auto offset, size, name, i;
    for (i = 0; i < count; ++i) {
        //Message("Checking member %x\n", pointer);
        
        
        offset = Dword(pointer);
        pointer = pointer + 4;

        size = Dword(pointer);
        pointer = pointer + 4;

        name = GetString(Dword(pointer), -1, 0);
        pointer = pointer + 4;
        
        
        //Message("var \"%s\", at %x, size %d\n trying [bp-0X%X] %x\n", name, offset, size, -offset, GetFunctionAttr(address, FUNCATTR_START));
        
        auto format = form("[bp-0X%X]", -offset);
        
        //does not work
        //MakeLocal(GetFunctionAttr(address, FUNCATTR_START), GetFunctionAttr(address, FUNCATTR_END), format, name);
        
        Message("    Variable : \"%s\", Offset -0x%X, size 0x%X\n", name, -offset, size);
    }
    
    Message("=== End of Stack Vars for 0x%X\n\n", start);
}

static main()
{
    auto checkfunc;
    checkfunc = LocByName("j_@_RTC_CheckStackVars@8");
    
    if (checkfunc == BADADDR)
    {
        checkfunc = LocByName("@_RTC_CheckStackVars@8");
    }
    
    if (checkfunc == BADADDR){
        Message("Please name RTC_CheckStackVars\n");
        return;
    }
    
    auto addr;
    for (addr = RfirstB(checkfunc); addr != BADADDR; addr = RnextB(checkfunc, addr)) {
        Read_CheckVar_Array(addr);
        //break;//test code
    }
}