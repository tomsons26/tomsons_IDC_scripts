//
// wrapper_maker.idc
//by tomsons26
// Converts a demangled name to a wrapper call
//
// Written for at least a little automating writing wrappers
// for unimplamented functions, likely has issues and
// likely works only for class functions in Watcom

#include <idc.idc>

static Print_Prototype(classtype, prottype)
{
    Message("(");
    //check for a class
    if (classtype != "")
    {
        //print class name
        Message("%s *", classtype);
    }
    
    //check if return is void
    if (prottype == "void" && prottype != "void *"){
        //if so end proto definition
        Message(")");
    }
    else
    {
        //check for class
        if (classtype != "")
        {
            //if so since we have more proto members
            Message(", ");
        }
        //print the proto
        Message("%s)", prottype);
    } 
}

static main()
{
    //Fetch the current function name
    auto name = Demangle(GetTrueName(GetFunctionAttr(here, FUNCATTR_START)), INF_LONG_DN);
    
    auto nearloc;
    auto rettype, funcname, prottype, classtype;

    //hack, relies on near being in string to work
    nearloc = strstr(name, "near");
    if (nearloc != -1) {
        
        //get return type
        rettype = substr(name, 0, nearloc);
        
        //get function name
        funcname = substr(name, nearloc + 5, strstr(name, "("));
        
        //get prototype
        prottype = substr(name, strstr(name, "(") + 1, strstr(name, ")"));

        //get class if there is one
        if (strstr(name, "::") != -1)
        {
            classtype = substr(name, strstr(name, "near ") + 5, strstr(name, "::"));
        }
        
        // print function definition
        Message("%s%s", rettype, funcname);
        if (prottype == "void" && prottype != "void *"){
            //proto has no members
            Message("()\n");
        } else {
            //else we print proto
            Message("(%s)\n", prottype);
        }
        
        //print wrapper
        Message("{\n#ifndef CHRONOSHIFT_STANDALONE\n");
        Message("    %s(*func)", rettype);
        Print_Prototype(classtype, prottype);
        
        // print function definition
        Message(" = reinterpret_cast<%s(*)", rettype);
        Print_Prototype(classtype, prottype);
        
        //print address of function
        Message(">(0x%08X);\n", GetFunctionAttr(here, FUNCATTR_START));
        //check for a return type
        if (rettype == "void " && rettype != "void *"){
            Message("    func(this);\n");
        } else {
            Message("    return func(this);\n");
        }

        //print end of function
        Message("#else\n");
        Message("    DEBUG_ASSERT_PRINT(false, \"Unimplemented function '%%\s\' called!\\n\", __FUNCTION__);\n");
        if (rettype == "void " && rettype != "void *"){
            //do nothing
        } else {
            Message("    return 0;\n");
        }
        Message("#endif\n}\n");
    } else {
        Message("near not found!\n");
    }
      
}
