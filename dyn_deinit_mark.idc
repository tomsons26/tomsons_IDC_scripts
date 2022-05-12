//
//Dynamic Deinit Marker
//by tomsons26
//Marks dynamic deinits as dark grey
//This is useful to establish boundries of modules
//TODO dunno
//

#include <idc.idc>
#define THRESHOLD 50 //tweak this if something gets skipped

static main(void)
{
	auto func_addr = 0;
    auto found = 0;
    auto do_set = 0;
    auto func_name = 0;
    auto deinit_addr = 0;

    func_addr = LocByName("_atexit");
    
    if (func_addr == BADADDR) {
        return;
    }

    auto xref = RfirstB(func_addr);
    while( xref != BADADDR )
    {    
        //Message("atexit at %x\n", xref);
        found = FindBinary(xref, SEARCH_UP, "68");
        if (found == BADADDR) {
            break;
        }
        
        // if found is more than a threshold thats far away enough
        if (found > func_addr + THRESHOLD) {
            do_set = 1;
        // if found is less than a threshold thats far away enough
        } else if (found < func_addr - THRESHOLD) {
            do_set = 1;
        // else the pattern was found too close so we don't set func_name
        } else {
            do_set = 0;
        }
        
        deinit_addr = Dword(found + 1);
        if (do_set) {
            func_name = get_func_name(deinit_addr);
            if (strlen(func_name) >= 4 && strstr(func_name, "sub_") != -1) {
            
                func_name = "static_deinit_" + substr(func_name, 4, -1);
                
                //Message("naming %x, %s\n", deinit_addr, func_name);
                MakeName(deinit_addr, func_name);
            }
            
            SetColor(deinit_addr, CIC_FUNC, 0xd7d7d7);
        }
        
        found = BADADDR;
        xref = RnextB(func_addr, xref);
    }
}