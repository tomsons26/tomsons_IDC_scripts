// print_vtable.idc
// Fetches the class name from the vtable and prints
// specified mangled names with the class name included.

#include <idc.idc>

static main()
{
    auto pAddress;
    auto structName;

    // User selected vtable block
    pAddress = ScreenEA();

    if (pAddress == BADADDR) {
        Message("** No vtable selected! Aborted **");
        Warning("No vtable selected!\nSelect vtable block first.");
        SetStatus(IDA_STATUS_READY);
        return;
    }
    
    //try Getting Name from Vtable itself, else set a preset
    structName = GetTrueNameEx(pAddress, pAddress);
    // make sure we have a name and it has a char typical to mangled names
    if (structName != "" && strstr(structName, "off_") == -1) {
        //MSVC/GCC Old
        if(strstr(structName, "??") != -1 || strstr(structName, "__vt") != -1){
            structName = Demangle(structName, INF_SHORT_DN);
            structName = substr(structName, 0, strstr(structName, "::"));
        }
        //GCC New
        if(strstr(structName, "_Z") != -1 ){
            structName = Demangle(structName, INF_SHORT_DN);
            structName = substr(structName, strstr(structName, "'") + 1, strstr(structName, "::"));
        }
        //Watcom
        if(strstr(structName, "W?") != -1 ){
            Message("substring - %s\n", substr(structName, strstr(structName, ":") + 1, strstr(structName, "$$")));
            structName = substr(structName, strstr(structName, ":") + 1, strstr(structName, "$$"));
        }
    } else {
        structName = "class";
        structName = AskStr(structName, "Can't get class name\nEnter it");
    }

    Message("=======================================================\n");
    Message("?QueryInterface@%s@@UAGJABU_GUID@@PAPAX@Z\n", structName);
    Message("?AddRef@%s@@UAGKXZ\n", structName);
    Message("?Release@%s@@UAGKXZ\n", structName);
    Message("?GetClassID@%s@@UAGJPAU_GUID@@@Z\n", structName);
    Message("?IsDirty@%s@@UAGJXZ\n", structName);
    Message("?Load@%s@UAGJPAUIStream@@@Z\n", structName);
    Message("?Save@%s@@UAGJPAUIStream@@H@Z\n", structName);
    Message("?GetSizeMax@%s@@UAGJPAT_ULARGE_INTEGER@@@Z\n", structName);
    Message("??_E%s@@UAEPAXI@Z\n", structName);
    Message("=======================================================\n");
}