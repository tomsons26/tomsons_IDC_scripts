//
// wrapper_maker.idc
//by tomsons26
// Converts a demangled name to a wrapper call
//
// Written for at least a little automating writing wrappers
// for unimplamented functions, likely has issues and
// likely works only for class functions in Watcom

#include <idc.idc>

static Is_Void(checktype)
{
    if (checktype == "void const" ){
        return 1;
    }
    
    if (checktype == "void *") {
        return 0;
    }
    if (checktype == "void ") {
        return 1;
    }
    if (checktype == "void") {
        return 1;
    }
    return 0;
}

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
    if (Is_Void(prottype)){
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


static Count_Prototype_Members(prottype)
{
    auto count, i;
    count = 0;
    if (!Is_Void(prottype)) {
        count++;
    }
    
    for (i = 0; i < strlen(prottype); i++) {
        if (prottype[i] == ",") {
            count++;
        }
    }
    return count;
}

static Clean_Up_Return(rettype)
{
    return substr(rettype, 0, strstr(rettype, "const"));
}

static main()
{
    //Fetch the current function name
    auto name = Demangle(GetTrueName(GetFunctionAttr(here, FUNCATTR_START)), INF_LONG_DN);
    auto nearloc, memb_count;
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
        Message("%s%s", Clean_Up_Return(rettype), funcname);
        
        //print proto
        Message("(");
        if (!Is_Void(prottype)){
            Message("%s", prottype);
        }
        Message(")\n");
        
        //print wrapper
        Message("{\n#ifndef CHRONOSHIFT_STANDALONE\n    ");
        Message("%s(*func)", Clean_Up_Return(rettype));
        Print_Prototype(classtype, prottype);
        
        // print function definition
        Message(" = reinterpret_cast<%s(*)", Clean_Up_Return(rettype));
        Print_Prototype(classtype, prottype);
        
        //print address of function
        Message(">(0x%08X);\n", GetFunctionAttr(here, FUNCATTR_START));
        
        //print call
        Message("    ");//spacing
        if (!Is_Void(rettype)){
            Message("return ");
        }
        
        Message("func(");
        if (classtype != "") {
            Message("this");
        }
        
        //write dummy args
        memb_count = Count_Prototype_Members(prottype);
        if (memb_count != 0) {
            if (classtype != "") {
                Message(", ");
            }
            auto i;
            for (i = 0; i < memb_count; i++) {
                Message("a%d", i+1);
                if (i != (memb_count - 1)) {
                    Message(", ");
                }
            }
        }
        Message(");\n");
        
        //print end of function
        Message("#else\n");
        Message("    DEBUG_ASSERT_PRINT(false, \"Unimplemented function called!\\n\");\n");
        if (!Is_Void(rettype)){
            Message("    return 0;\n");
        }
        Message("#endif\n}\n");        
    } else {
        Message("near not found!\n");
    }
      
}
