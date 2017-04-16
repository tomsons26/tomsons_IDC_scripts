//
// Dump specific comment script
// by tomsons26
//
// Search comment strings, for example from a imported symbol table, where the line numbers and source files are commented
//

#include <idc.idc>


static main()
{
  auto Path, Handle;
  auto Comment;
 
  
//  Path = AskFile (1, "*.txt", "Text file to save output to");
//  if (Path == "") {
//    return;
//  }

//	Handle = fopen(Path, "w");
//	if (!Handle) {
//	return;
//	}
  
	Comment = AskStr("", "Enter String to Search for:\n");

	if (Comment != 0)
	{
	//Print_Comments(Comment, Handle);
	Print_Comments(Comment);
	}
}

//static Print_Comments(Comment, handle)
static Print_Comments(comment)
{
	auto Address, Function_Comment;
	auto Function_Name, Demangled;

	Message("//Start of list.\n//\n//\n");

	for (Address = 0; Address != BADADDR; Address = NextFunction(Address))
	{
			Function_Comment = GetFunctionCmt(Address, 1);
	
			if (Function_Comment != "")
			{
				if (strstr(Function_Comment, comment) != -1)
				{
					//print comment
					//fprintf(handle,"//comment %s\n", Function_Comment);
					//Message("//comment %s\n", Function_Comment);
	  
					Function_Name = GetFunctionName(Address);
					Demangled = Demangle(Function_Name, INF_LONG_DN);
		
					if (Demangled == "") 
					{
						Demangled = Function_Name;
					}
					//fprintf(handle, "%s\n", Demangled);
					Message("%s\n", Demangled);
				}
			}
	}
	Message("// End of list.\n");	
}
