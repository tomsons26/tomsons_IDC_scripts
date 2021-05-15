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

    auto parse = 0;

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
            ++i;
        
            SetColor(Dword(addr), CIC_FUNC, 0xd7d7d7);
            addr = addr + 4;
            
        }
    } else {
        Message("Can't find dynamic init list or binary not compatible with script!\n");
    }
}