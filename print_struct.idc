//
//Print Struct script
//by tomsons26
//printout style is deliberately matched with what Watcom's dump_object_model pragma generates
//can be easily modified to conform with MSVC /d1reportSingleClassLayoutXXX /d1reportAllClassLayout or GCC equal

#include <idc.idc>

static Print_Val(val)
{
    
    //prints hex as well only if value above 4
    if (val > 4) {
        return form("%d/0x%x", val, val);
    } else {
        return form("%d", val);
    }
    
}

static Print_Struct(name)
{
    auto id, idx, m;
    id = GetStrucIdByName(name);
    if (id == -1) {
        Message("Could not Fetch Struct %s!\n", name);
        return -1;
    }
    Message("Reading struct %s\n", name);
    Message("   size:%s\n", Print_Val(GetStrucSize(id)));
    for (m = 0; m != GetStrucSize(id); m = GetStrucNextOff(id, m)) {
        auto mname;
        mname = GetMemberName(id, m);
        if (mname == "") {
            Message("   Hole (%d bytes)\n", GetStrucNextOff(id, m) - m);
        } else {
            Message("   member:  %s, offset = %s size = %s\n", GetMemberName(id, m), Print_Val(m), Print_Val(GetMemberSize(id, m)));
        }
    }
}

static main()
{
    Message("Structure Print Script loaded!\n");
    Message("to use type in Print_Struct(""\"STRUCTNNAME""\") in IDA Console\n");
}