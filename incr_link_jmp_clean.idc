//by tomsons26
//cleans up incremental linking jmps by patching call sites to real function
#include <idc.idc>

static get_relative_jmp_target(a)
{
    auto b;
    b = Byte(a);
    if (b == 0xEB) {
        b = Byte(a+1);
        
        if (b&0x80) {
          return a+2-((~b&0xFF)+1);
        } else {
          return a+2+b;
        }
      
    } else if (b==0xE9) {
        b = Dword(a+1);
        
        if (b&0x80000000) {
          return a+5-(~b+1);
        } else {
          return a+5+b;
        }
      
    } else {
      return BADADDR;
    }
}

//flip to 0 for testing
#define do_patch 1

static patch_addr(i, adr, seg_end)
{
    auto patch = 0;
    
    // is it code?
    if (i <= seg_end) {
        if (Byte(i) == 0x68) {
            //push offset, skip push
            i = i + 1;
            patch = 1;
        } else if (Byte(i) == 0xE8) {
            //call, skip call
            i = i + 1;
            patch = 1;  
        } else if (Byte(i) == 0xE9) {
            //jmp, skip jmp
            i = i + 1;
            patch = 1;
        } else if (Byte(i) == 0xC7) {
            //mov dword ptr, skip mov
            i = i + 3;
            patch = 1;
        } else {
            Message("Unpatched code ref at %08X\n", i);
        }
    // else its data
    } else {
        patch = 1;
    }
    
#ifdef do_patch
    if (patch) {
        PatchDword(i, adr);
    }
#endif
}

static clear_jump(adr, end)
{
#ifdef do_patch
    if (adr >= end || adr == BADADDR) {
        return;
    }
    
    PatchByte(adr, 0x90);
    PatchDword(adr + 1, 0x90909090);
#endif
}

static fixup_function_refs(a, seg_end)
{
    auto i, c, relative;
    
    i = RfirstB(a);
    c = get_relative_jmp_target(a);
    
    //fixup calls
    while(i != BADADDR) { 
        if (c == BADADDR) {
            Message("foooo\n");
            break;
        }
    
        //is this a call or jmp?
        if (Byte(i) == 0xE8 || Byte(i) == 0xE9) {
            relative = c - i - 5;
            Message(form("jump at %08X call %08X actual %08X relative %08X\n", a, i, c, relative));
            patch_addr(i, relative, seg_end);
        }
        i=RnextB(a,i);
    }
    
    auto f;
    
    i = DfirstB(a);
    f = Rfirst(a);
    
    //fixup data
    while(i != BADADDR) {
        Message("data at %08X - to %08X - actual %08X\n",i, a, f);
        patch_addr(i, f, seg_end);
        i=DnextB(a,i);
    }
}

//set to address after last jmp
#define end 0x100028EC

static main()
{
    auto adr = MinEA();
    auto seg_end = SegEnd(adr);
    
    while (1) {
        adr = FindCode(adr, 3);
        
        if (adr >= end || adr == BADADDR) {
            break;
        }
        
        //ignore exports as not possible to fixup
        if (strstr(get_extra_cmt(adr, E_PREV + 0), "Exported entry") != -1) {
            continue;
        }
        
        if (Byte(adr) == 0xE9) {  
            fixup_function_refs(adr, seg_end);   
            Message("cleaning %x\n", adr);
            clear_jump(adr, end);
        }
    }
    
    AnalyseArea(MinEA(), -1);
}