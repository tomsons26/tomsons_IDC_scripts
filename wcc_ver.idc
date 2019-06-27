//
//Watcom Version Checker
//by tomsons26
//Checks Watcom version based on a identified change made in 10.6 to ftell and 10.5A in fclose
//Tested only on NT binaries
#include <idc.idc>

static main() 
{
    auto base;
    auto addr1, addr2, addr3;
    base = MinEA();
    
    //10.6 ftell chunk
    addr1 = FindBinary(base, SEARCH_DOWN, "F6 42 0C 80 74 0D F6 42 0D 10 74 07");
    //pre 10.6 ftell chunk
    addr2 = FindBinary(base, SEARCH_DOWN, "F6 42 0D 10 74 05 8D 0C 1E EB 02 29");
    //pre 10.5A fclose
    addr3 = FindBinary(base, SEARCH_DOWN, "53 52 89 C3 FF 15 ? ? ? ? A1 ? ? ? ? 85 C0 75 08 B8 FF FF FF FF 5A 5B C3 3B 58 04 74 04 8B 00 EB EB FF 15 ? ? ? ? BA 01 00 00 00 89 D8 E8 ? ? ? ? 5A 5B C3");

    if (addr1 != BADADDR) {
        Message("Watcom Version Checker - This is a Watcom 10.6 or later binary\n\n");
    } else if (addr2 != BADADDR) {    
        if (addr3 != BADADDR) {
            Message("Watcom Version Checker - This is a Watcom 10.5 or earlier binary\n\n");         
        } else {
            Message("Watcom Version Checker - This is a Watcom 10.5A binary\n\n");
        }
    } else {
        Message("Watcom Version Checker - Can't indentify compiler version\n\n");
    }
}