//
//Watcom Fixups
//by tomsons26
//Fixes up watcom startup and compiler specs when loading a windows watcom binary
//place in plugins dir, will run on loading a file or idb
//Tested only on NT binaries
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

static fixup_watcom_startup()
{
    auto found = BADADDR;

    // find "WATCOM C/C++32 Run-Time " string
    found = FindBinary(0, SEARCH_DOWN, "57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20");
    if (found == BADADDR) {
        // find "Open Watcom C/C++32 Run-Time. "
        found = FindBinary(0, SEARCH_DOWN, "4F 70 65 6E 20 57 61 74 63 6F 6D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 2E 20");
    }

    if (found != BADADDR) {
    
        Message("---- Fixing Watcom Startup function and compiler ID ----\n");

        //can't let IDA do analysis until right Watcom specs are set
        Analysis(0);

        //Message("---- Watcom Signature found at %X\n", found);
        auto saddr = found - 0x13;
        auto eaddr = saddr + 0xF;
        
        //make sure its a startup
        if (Byte(saddr) == 0xC7) {
            //DelFunction(saddr);
            //MakeFunction(saddr, eaddr);
            
            //fixup startup end
            SetFunctionEnd(saddr, eaddr);
            
            //fixup startup names
            MakeName(saddr, "_wstart2_");
            MakeName(Dword(saddr + 0x2), "__WinMainProc");
            MakeName(Dword(saddr + 0x6), "_WinMain@16");
            MakeName(get_relative_jmp_target(saddr + 0xA), "__WinMain");
                    
            Message("---- Fixed Watcom Startup function %X - %X ----\n", saddr, eaddr);
            
            // don't want to break existing idb settings
            if (get_inf_attr(INF_COMPILER) != COMP_WATCOM) {
                set_inf_attr(INF_COMPILER, COMP_WATCOM); //set compiler as watcom if not set already
                set_inf_attr(INF_MODEL, 115); // set fastcall(actually watcall)
                set_inf_attr(INF_SIZEOF_ALGN, 1); //watcom pads to 1
            }
            
            Message("---- Set Watcom Compiler specs ----\n");
            
            // everything properly set up, proceed
            Analysis(1);
            Message("---- Watcom fixups done! ----\n");
        } else {
            Message("Found Watcom signature but not startup?!\n");
        }
    }
}

class wcplugin_t
{
  wcplugin_t()
  {
    this.flags = PLUGIN_UNL | PLUGIN_HIDE;
    this.comment = "Fixup Watcom stuff";
    this.help = "Fixup Watcom stuff";
    this.wanted_name = "Fixup Watcom stuff";
    this.wanted_hotkey = "";
  }

  init()
  {
    if (LocByName("_wstart2_") != BADADDR) {
        Message("---- Watcom fixups already ran! ----\n");
    } else if (0) {
        //detect watcom using cdecl and dos extender
    } else {
        fixup_watcom_startup();
    }

      
    
    //msg("%s: init() has been called\n", this.wanted_name);
    return PLUGIN_OK;
  }

  run(arg)
  {
    msg("%s: run() has been called with %d", this.wanted_name, arg);
    return (arg % 2) == 0;
  }

  term()
  {
    //msg("%s: term() has been called\n", this.wanted_name);
  }
}

static PLUGIN_ENTRY()
{
  return wcplugin_t();
}
