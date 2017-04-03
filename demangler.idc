//
//Batch Demangler
//by tomsons26
//Demangles names if it can, if not prints original.
//It writes to output window, perhaps should be upgraded to print to a file
//

#include <idc.idc>

static main()
{
Demangle_Name("??0MyClass@@QAE@XZ");
}

static Demangle_Name(mangled)
{
	auto func_name;
	
	func_name = Demangle(mangled, INF_LONG_DN);//Short demangled name is INF_SHORT_DN
	
	//If demangled result blank use original string
	if (func_name == "")
	{
	func_name = mangled;
	}

	Message("	%s\n", func_name);
}
