// vtable_to_struct.idc
// Converts a VTable to a struct
// Based on VTableRec.idc by Sirmabus and modified by BAILOPAN
// Modified again by tomsons26 to strip class name, name dtors/sdtors and index functions with same name

// Possibly Todo
// Verify some possible fringe cases
// Script gets stuck on unusable symbols such as MSVC SDTOR `(fixed)
// watch out for other cases like these

#include <idc.idc>

static CleanupName(name)
{
	auto i;
	auto current;
    auto StrLoc, length;
    auto substr1, substr2;
	length = strlen(name);    


    //Remove class name if any
    StrLoc = strstr(name, "::");
    if (StrLoc != -1)
    {
        substr1 = substr(name, 0, StrLoc);
        substr2 = substr(name, StrLoc + 2, -1);
        //Message("substring 1 %s substring 2 %s\n", substr1, substr2);
        //check for CTOR
		if (substr1 != -1 && substr2 != -1 && substr1 == substr2)
		{
            //Message("Got a CTOR\n");
			return "CTOR";
		}
        name = substr2;
    }

	for(i = 0; i < strlen(name); i++)
	{
		current = name[i];
		if(current == ":")
		{
			name[i] = "_";
		}
        //If we got a DTOR just return DTOR
        if (current == "~")
        {
             return "DTOR";
        }
        //If we got a SDTOR just return SDTOR
        if (current == "`")
        {
             return "SDTOR";
        }
	}

	return name;
}

static main()
{
	auto pAddress, iIndex;
	auto skipAmt;
	auto structName;
	auto structID;

	SetStatus(IDA_STATUS_WORK);

	// User selected vtable block
	pAddress = ScreenEA();
	
	if (pAddress == BADADDR)
	{	   
		Message("** No vtable selected! Aborted **");
		Warning("No vtable selected!\nSelect vtable block first.");													 
		SetStatus(IDA_STATUS_READY);
		return;
	}

	SetStatus(IDA_STATUS_WAITING);
	
	// Ask for settings
	skipAmt = AskLong(0, "Number of vtable entries to ignore for indexing:");
	structName = AskStr("CClass_vtable", "Enter the name of the vtable struct:");
	
	SetStatus(IDA_STATUS_WORK);
	
	// If the vtable struct already exists, delete it
	structID = GetStrucIdByName(structName);
	if (structID != -1)
	{
		Message("Deleted old vtable struct\n");
		DelStruc(structID);
	}
	
	// Create the struct to import vtable names into
	structID = AddStruc(-1, structName);
	
	auto szFuncName, szFullName, szCleanName;

	// For linux, skip the first entry
	if (Dword(pAddress) == 0)
	{
		pAddress = pAddress + 8;
	}
	
	pAddress = pAddress + (skipAmt * 4);

    auto docheck = 0;
	// Loop through the vtable block
	while (pAddress != BADADDR)
	{		
        // check for a name, this is for such cases
        // when there's no padding after the vtable
        // else it will keep exporting it
        if (docheck)
        {
            if (strstr(NameEx(pAddress, pAddress), "?") != -1)
            {
                break;
            }
        }
        
		szFuncName = GetFunctionName(Dword(pAddress));
		if (strlen(szFuncName) == 0)
		{
			break;
		}
		
		szFullName = Demangle(szFuncName, INF_SHORT_DN);
		if (szFullName == "")
		{
			szFullName = szFuncName;
		}
		
		if (strstr(szFullName, "_ZN") != -1)
		{
			Warning("You must toggle GCC v3.x demangled names!\n");
			DelStruc(structID);
			break;
		}

		szCleanName = CleanupName(szFullName);

        auto funindex = 0;
        auto NameToTry = szCleanName;
		while (AddStrucMember(structID, NameToTry, iIndex * 4, 0x20000400, -1, 4) == STRUC_ERROR_MEMBER_NAME)
		{
            funindex++;
			NameToTry = szCleanName + "_" + ltoa(funindex, 16);
		};
        funindex = 0;

		pAddress = pAddress + 4;
		iIndex++;
        docheck = 1;
	};

	Message("Successfully added %d vtable entries to struct %s.\n", iIndex, structName);
	Message("\nDone.\n\n");
	SetStatus(IDA_STATUS_READY);
}