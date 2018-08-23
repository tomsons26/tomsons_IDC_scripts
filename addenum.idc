//
//Add to Enum script
//by tomsons26
//Script to speed up naming enums in a situation where a switch resolves a enum to a string
//In pseudo, place cursor at case OR (depending on code),
// function call with string and press the hotkey

#include <idc.idc>

//tries finding a string in specified location
//extend if needed as needed
static try_getting(index)
{
    if (index == 0){
        return GetString(GetOperandValue(here + 6, 0), -1, 0);  
    }
    if (index == 1){
        return GetString(GetOperandValue(here - 7, 0), -1, 0);
    }
}

static Add_Enum()
{
    auto enumval, i;
    auto enumstring;
    
    //try getting the string
    for (i = 0; i < 1; i++)
    {
        enumstring = try_getting(i);
        if (enumstring != "")
        {
            break;
        }
    }
    
	if(enumstring == "")
	{
		Message("Could not Get string!");
	}

    enumval = AskLong(-1, form("Found String %s\nEnter value to use for Enum", enumstring));
    //If got -1(Cancel) stop execution
	if(enumval == -1)
	{
		return;
	}
    
    //Edit GetEnum call string as needed
    AddConstEx(GetEnum("MessageType"), enumstring, enumval, -1);
    Message("Attempted to add %s as value %d\n", enumstring, enumval);

}

static main(void)
{
	AddHotkey("8", "Add_Enum");
}