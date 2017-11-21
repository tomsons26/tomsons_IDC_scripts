//
//No Return Cleaner
//by tomsons26
//Removes No Return flag from functions as it breaks decompilation of most of the db.
//Common cause for this mess is a plugin doing something that makes IDA do this.
//

#include <idc.idc>

#define printonly false
#define demangle false

static print_functions()
{
  auto ea, i;
  Message("///////////////////////////////\n");
  for ( ea=NextFunction(0); ea != BADADDR; ea=NextFunction(ea) )
  {

    auto mangled = GetFunctionName(ea);
    auto func_name = "";
    
    if (demangle)
    {
	func_name = Demangle(mangled, INF_LONG_DN);//Short demangled name is INF_SHORT_DN
    }
    if (func_name == "")
	{
        func_name = mangled;
	}  
    if (GetFunctionFlags(ea) & FUNC_NORET)
    {
        Message("No Return Function at %08lX: %s\n", ea, func_name);
    i++;
    }
  }
  Message("Found %d No Return Functions\n", i);
  Message("///////////////////////////////\n");
}

static remove()
{
  auto ea, i;
  for (ea=NextFunction(0); ea != BADADDR; ea=NextFunction(ea))
  {   
    if (GetFunctionFlags(ea) & FUNC_NORET)
    {
        SetFunctionFlags(ea, GetFunctionFlags(ea)&~FUNC_NORET);
    i++;
    }
  }
  Message("Removed 'Does not return' from %d Functions\n", i);
  Message("///////////////////////////////\n");
}


static main()
{
    if (printonly)
    {
        print_functions();
    }
    
    else
    {
        print_functions();
        remove();
    }
}