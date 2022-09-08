//
//Dynamic Init Marker
//by tomsons26
//Marks dynamic inits as dark grey
//This is useful to establish boundries of modules
//TODO probably some dummy naming too, try looking into marking dynamic denits these call
//

#include <idc.idc>

static main()
{
    auto addr;

    auto prefix = 1;
    auto parse = 0;
    auto name = 0;

    //!! change segment name if needed
    auto segm = get_segm_by_sel(SegByName(".data"));
    //auto segm = get_segm_by_sel(SegByName(".rdata"));
    Message("segment at 0x%X\n", segm);
    
    //is the address valid, does it start with 0 as MSVC dyn init list starts, is it a msvc binary
    if (segm != BADADDR) {

        // cover binaries that have 0s as first entries
        if (Dword(segm) == 0) { 
            // skip over the 0
            addr = segm + 4;
        } else {
            // skip over the guard
            addr = segm + 4;
            // skip over the 0
            addr = addr + 4;
        }
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
            ++i;
        
            if (prefix) {
                name = get_func_name(Dword(addr));
                if (strlen(name) >= 4 && strstr(name, "sub_") != -1) {
                    name = "static_init_" + substr(name, 4, -1);
                    MakeName(Dword(addr), name);
                    //Message("naming %x, %s\n", Dword(addr), name);
                }
            }
        
            SetColor(Dword(addr), CIC_FUNC, 0xd7d7d7);
            addr = addr + 4;
            
        }
    } else {
        Message("Can't find dynamic init list or binary not compatible with script!\n");
    }
}