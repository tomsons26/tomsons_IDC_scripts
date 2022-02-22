//
// Reads a specifically formatted parse table and prints out (almost) usable code
// by tomsons26
// Place cursor at table start and run the script

#include "idc.idc"

//auto id = GetStrucIdByName("GlobalData");
//
//Message("ID is %x\n", id);
//
//auto name = GetMemberName(id, 0x729 + 1);
//
//Message("name is %s\n", name);

static Get_Name(address)
{
    return GetString(address, -1, 0);
}

static Get_Offset_String(struct_name, member_offset)
{
    auto struct_id = GetStrucIdByName(struct_name);
    
    auto final_name;

    final_name = "FIXME";

    if (member_offset == 0) {
        // usually there isn't a member at 0 so return 0
        return "0 }";
    }

    auto name = GetMemberName(struct_id, member_offset);
    auto offset = GetMemberOffset(struct_id, name);
    
    if (member_offset == offset) {
        final_name = name;
    } else {
        //Message("// ERROR, member offset doesn't match\n");
    }
    

    return form("offsetof(%s, %s) }", struct_name, final_name);
}
    
static Get_Symbol_Name(address, is_ptr)
{    
    auto name_start = 0;
    auto name_end = -1;

    address = Dword(address);
    
    if(address == 0) {
        
        return "nullptr";
    }


    auto name = Name(address);
    
    //Message("got %s", name);
    //todo investigate can we get the name only without args or return though demangle args
    //auto dname = Demangle(name,1);
    
    auto compiler = GetCharPrm(INF_COMPILER);
    if (compiler == COMP_MS) {

        // this is for MSVC mangled symbols
        name_start = strstr(name, "?");
    
        if (name_start == -1) {
            name_start = 0;
        } else {
            //skip over ?
            name_start = name_start + 1;
        }
        
        name_end = strstr(name, "@");
    }
    
    if (compiler == COMP_GNU) {
        //use demangled name for GCC
        auto dname = Demangle(name,1);
        
        //
        if (dname != 0) {
            name = dname;
            
            name_start = strstr(name, "::");
        
            if (name_start == -1) {
                name_start = 0;
            } else {
                //skip over ::
                name_start = name_start + 2;
            }
            
            name_end = strstr(name, "(");
            
        } else {
            //failed to mangle leave alone
        }
        

    }
    
    auto fname = substr(name, name_start, name_end);
    
    return fname;
}

static Validate_String(string)
{
    if (string == "") {
        return 0;
    }
    
    return 1;
}

static Parse_Table(address, struct_name, count)
{
    auto i = count;
    
    auto addr = address;
    
    auto token;
    auto parse;
    auto user_data;
    auto offset;
    
    auto ok = 0;
    
    while(i != 0) {
        token = Get_Name(Dword(addr));
        ok = Validate_String(token);
        if (!ok){
            //Probably at end of list
            break;
        }
        
        addr = addr + 4;
        
        parse = Get_Symbol_Name(addr, 1);
        ok = Validate_String(parse);
        if (!ok){
            Message("ERROR -------- Something went reading parse!");
            break;
        }
        
        addr = addr + 4;
        
        auto val = Dword(addr);
        
        // is this less than most likely value?
        if (val < 0x00001000) {
            // the user data is a int
            user_data = form("%d", val);
        } else {
            user_data = Get_Symbol_Name(addr, 1);
            ok = Validate_String(user_data);
            if (!ok){
                Message("ERROR -------- Something went reading user_data!");
                break;
            }
        }
        
        addr = addr + 4;
        
        offset = Get_Offset_String(struct_name, Dword(addr));
        ok = Validate_String(offset);
        if (!ok){
            Message("ERROR -------- Something went reading offset!");
            break;
        }
        
        addr = addr + 4;
        
        Message(
        "{ \"%s\",\t"
        "&%s,\t"
        "%s,\t"
        "%s,\t\n", 
        token,
        parse,
        user_data,
        offset
        );
        
        i = i - 1;
    }
    
    // table needs to end with nulls
    Message(
    "{ nullptr,\tnullptr,\tnullptr,\t0 },\n");
}

static main()
{
    auto addr = ScreenEA();
    
    auto struct_name = AskStr(struct_name, "Set the name the struct:");
    if (struct_name == "") {
        Message("No Struct Name!\n");
        return;
    }
    
    // think this is well above largest
    // the script should bail if it encounters a null entry
    // so this shouldn't cause a infinite loop
    //
    // increase if need be
    auto count = 500;
    
    //count = AskLong(0, "Number entries to parse:");
    //if (count == 0 || count == 999) {
    //    Message("No entry count!\n");
    //    return;
    //}
    
    auto struct_id = GetStrucIdByName(struct_name);
    
    if (struct_id == -1) {
        Message("Can't get struct %s!\n", struct_name);
        return;
    }
    
    Parse_Table(addr, struct_name, count); 
}