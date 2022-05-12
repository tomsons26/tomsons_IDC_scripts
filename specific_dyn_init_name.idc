//
//Dynamic Init Namer written specifically for TS/RA2/YR
//by tomsons26
//

#include <idc.idc>

static Get_Name(addr)
{
    auto function_size = GetFchunkAttr(addr,FUNCATTR_END)-GetFchunkAttr(addr,FUNCATTR_START);
    
    if (function_size >= 64 + 32) {
        // these are not the static inits you are looking for
        return "";
    }

    auto result = BADADDR;
    auto do_set = 0;

    auto found = 0;
    auto extra = 0;
    
    if (!found) {
        // fld
        result = FindBinary(addr, SEARCH_DOWN, "DD 05");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_math";
        
            result = FindBinary(addr, SEARCH_DOWN, "DD 05 ? ? ? ? DC 0D ? ? ? ? DD 1D ? ? ? ? C3");
            if (result != BADADDR && result <= addr + function_size) {     
                found = 1;
                // fld operand
                auto faddr = Dword(addr + 2);
                
                // is deg2rad, need to check on byte level
                if (Byte(faddr + 0) == 0x39 
                &&  Byte(faddr + 1) == 0x9D 
                &&  Byte(faddr + 2) == 0x52
                &&  Byte(faddr + 3) == 0xA2 
                &&  Byte(faddr + 4) == 0x46 
                &&  Byte(faddr + 5) == 0xDF 
                &&  Byte(faddr + 6) == 0x91 
                &&  Byte(faddr + 7) == 0x3F) {
                
                    // fmul operand
                    faddr = Dword(addr + 2 + 6);
                    
                    // is 45 degrees
                    if (GetDouble(faddr) == 45.0) {
                        extra = "_math_deg2rad" + "45";
                    }
                    
                    // is 60 degrees
                    if (GetDouble(faddr) == 60.0) {
                        extra = "_math_deg2rad" + "60";
                    }
                    
                    // is 90 degrees
                    if (GetDouble(faddr) == 90.0) {
                        extra = "_math_deg2rad" + "90";
                    }
                }
            }
        }
    }
        
    if (!found) {
        // fild
        result = FindBinary(addr, SEARCH_DOWN, "DB 05");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_math";
        }
    }  
    
    if (!found) {
        // fild
        result = FindBinary(addr, SEARCH_DOWN, "DB 44");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_math";
        }
    }
    
    if (!found) {
        // fmul
        result = FindBinary(addr, SEARCH_DOWN, "DC 0D");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_math";
        }
    }    
    
    if (!found) {
        // cell init
        result = FindBinary(addr, SEARCH_DOWN, "33 C0 66 A3 ? ? ? ? 66 A3 ? ? ? ? C3");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_cell";
        }
    }      
    
    if (!found) {
        // cell init
        result = FindBinary(addr, SEARCH_DOWN, "33 C0 68 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C6 05 ? ? ? ? ? A2 ? ? ? ? C7 05 ? ? ? ? ? ? ? ? C7 05 ? ? ?");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_dvc";
        }
    }    
        
    if (!found) {
        // coord(0,0,0) init
        result = FindBinary(addr, SEARCH_DOWN, "33 C0 A3 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C3");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_coord";
        }
    }    

    if (!found) {
        // coord(128, 128, 0) init
        result = FindBinary(addr, SEARCH_DOWN, "B8 ? ? ? ? C7 05 ? ? ? ? ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C3");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_coord";
        }
    }    
            
    if (!found) {
        // rect init
        result = FindBinary(addr, SEARCH_DOWN, "33 C0 A3 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C3");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_rect";
        }
    }    
    
    if (found) {
        return "static_init" + extra + "_00" + ltoa(addr, 16);
    }
    
    return "";
}


static main()
{
    auto addr;

    auto new_name = 0;
    auto parse = 0;
    auto name = 0;

    //!! change segment name if needed
    auto segm = get_segm_by_sel(SegByName(".data"));
    Message("segment at 0x%X\n", segm);
    
    //is the address valid, does it start with 0 as MSVC dyn init list starts, is it a msvc binary
    if (segm != BADADDR && Dword(segm) == 0 && GetCharPrm(INF_COMPILER) == COMP_MS) {
        // skip over the 0
        addr = segm + 4;
        parse = 1;
    }

    if (parse) {
        auto i = 0;
        while (1) {
        
            //end of list
            if (Dword(addr) == 0) {
                Message("Reached end of list, marked %d\n", i);
                break;
            }
            
            if (i == 10000){
                Message("Bugs happened, attempted to process absurd amount\nBaling to prevent inifnite loop\nLast address %X\n", addr);
                break;
            }
            
            
            ++i;
            
            name = Get_Name(Dword(addr));
        
            if (name != "") {
                //Message("here6\n");
                MakeName(Dword(addr), name);
                //SetColor(Dword(addr), CIC_FUNC, 0xd7d7d7);
                //Message("naming %x, %s\n", Dword(addr), name);
            }
            
            addr = addr + 4;
            
        }
    } else {
        Message("Can't find dynamic init list or binary not compatible with script!\n");
    }
}