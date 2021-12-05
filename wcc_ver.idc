//
//Watcom Version Checker
//by tomsons26
//Checks Watcom version based on a identified change made in 10.6 to ftell and 10.5A in fclose
//Tested only on NT binaries
#include <idc.idc>

static main() 
{
    auto base;
    base = MinEA();
    
    // 11.0B change - Input value range checking for strtod() has been improved for very small values.
    //
    // 11.0B strtod chunk
    auto addr11b = FindBinary(base, SEARCH_DOWN, "8B 45 DC 80 E4 7F 25 FF FF 00 00 3D FF 43 00 00 7C");
    
    // 10.6 undocumented change
    //
    // 10.6 __wcpp_2_ctor_array__ nullptr check
    auto addr106_1 = FindBinary(base, SEARCH_DOWN, "51 56 57 83 EC 24 89 C1 89 D6 89 DF 85 C0 74 31 89 E2 E8 ? ? ? ? 89 C3 8B 47 01 8B 57 0D 89 44 24");    
    
    // 10.6 change - The ftell() function could return an incorrect file position for a stream with buffer data for writing and opened for append.
    //
    // 10.6 ftell chunk
    auto addr106_2 = FindBinary(base, SEARCH_DOWN, "F6 42 0C 80 74 0D F6 42 0D 10 74 07");
    
    //pre 10.6 ftell chunk
    auto addrp106 = FindBinary(base, SEARCH_DOWN, "F6 42 0D 10 74 05 8D 0C 1E EB 02 29");
    
    //pre 10.5A fclose
    auto addr105a = FindBinary(base, SEARCH_DOWN, "53 52 89 C3 FF 15 ? ? ? ? A1 ? ? ? ? 85 C0 75 08 B8 FF FF FF FF 5A 5B C3 3B 58 04 74 04 8B 00 EB EB FF 15 ? ? ? ? BA 01 00 00 00 89 D8 E8 ? ? ? ? 5A 5B C3");

    if (addr11b != BADADDR) {
        Message("Watcom Version Checker - This is a Watcom 11.0B or later binary\n\n");
        return;
    } 
    
    if (addr106_1 != BADADDR) {
        Message("Watcom Version Checker - This is a Watcom 10.6 to Watcom 11.0B(excluding) binary. Matched Signature 1\n\n");
        return;
    }
   
    if (addr106_2 != BADADDR) {
        Message("Watcom Version Checker - This is a Watcom 10.6 to Watcom 11.0B(excluding) binary Matched Signature 2\n\n");
        return;
    } 

    if (addrp106 != BADADDR) {    
        if (addr105a != BADADDR) {
            Message("Watcom Version Checker - This is a Watcom 10.5 or earlier binary\n\n");  
            return;    
        }
        
        Message("Watcom Version Checker - This is a Watcom 10.5 binary\n\n");
        return;
    }
    
    Message("Watcom Version Checker - Can't indentify compiler version\n\n");

}