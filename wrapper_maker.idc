//
// wrapper_maker.idc
//by tomsons26
// Converts a demangled name to a wrapper call
//
// Written for at least a little automating writing wrappers
// for unimplamented functions, likely has issues and
// likely works only for class functions in Watcom

#include <idc.idc>
static main()
{
    //Fetch the current function name
    auto name = Demangle(GetTrueName(GetFunctionAttr(here, FUNCATTR_START)), INF_LONG_DN);
    
    auto nearloc;
    auto rettype, funcname, prottype, classtype;

    nearloc = strstr(name, "near");
    if (nearloc != -1) {
        
        //get return type
        rettype = substr(name, 0, nearloc);
        
        //get function name
        funcname = substr(name, nearloc + 5, strstr(name, "("));
        
        //get prototype
        prottype = substr(name, strstr(name, "(") + 1, strstr(name, ")"));

        //get class
        classtype = substr(name, strstr(name, "near ") + 5, strstr(name, "::"));
        
        //replace class with dummy if one was found
        //this may fail, not sure
        if (classtype == "")
        {
            classtype = "BAH";
        }
        
        // print function definition
        Message("%s%s", rettype, funcname);
        if (prottype != "void"){
        Message("(%s)\n", prottype);
        } else {
        Message("()\n");
        }
        
        //print wrapper
        Message("{\n#ifndef CHRONOSHIFT_STANDALONE\n");
        Message("    %s(*func)", rettype);
        Message("(%s *", classtype);
        
        //add additional proto args if there are such
        if (prottype != "void"){
        Message(", %s)", prottype);
        } else {
        Message(")");
        }
        
        // print function definition
        Message(" = reinterpret_cast<%s(*)", rettype);
        //add additional proto args if there are such
        Message("(%s *", classtype);
        if (prottype != "void"){
        Message(", %s)", prottype);
        } else {
        Message(")");
        }      
        
        //print address of function
        Message(">(0x%08X);\n    return func(this)\n", GetFunctionAttr(here, FUNCATTR_START));
        //print end of function
        Message("#else\n#endif\n}\n");
    } else {
        Message("near not found!\n");
    }
      
}
