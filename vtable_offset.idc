// Helper script for determining a vtable offset
//
// by tomsons26
//
// To use it run it, place the cursor on the vtable member you want
// the offset for and type in vtoff(); in the IDC command line

#include <idc.idc>

// FAILSAFE is for a case of a infinite loop so by any chance it can happen
#DEFINE FAILSAFE 2000

static vtoff()
{
    auto anyname, off, i;
    off = ScreenEA();
    for (i = 0; i < FAILSAFE; i++) {
        anyname = GetTrueNameEx(off - i * 4, off - i * 4);
        // if we got a name, stop, cause we possibly found the vtable start
        if (anyname != "") {
            break;
        }
    }
    Message("virtual offset is 0x%X\n", i * 4);
}
