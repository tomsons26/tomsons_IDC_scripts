//
//Semi automated Watcom Symbol loader Script
//by tomsons26
//
//The Load DWARF File has a flaw with Watcom ELF's,
//it doesn't account for the base address and loads at 0x0 base
//This automates rebasing it, loading the elf and restoring the base.

//PROBABLY_TODO
//figure out how to scan the input exe for the elf and extract it instead, if no elf do nothing
//Find out if its possible to pass the filename to the RunPlugin function somehow
//Figure out how to do this on startup when the binary is being loaded

#include <idc.idc>

static main() 
{
	auto Base, Compiler;

	//Wait for autoanalysis to complete before running the script
	Wait();

	//Check if the compiler is Watcom else bail
	Compiler = GetCharPrm(INF_COMPILER);
	if (Compiler != COMP_WATCOM)
	{
		Message("Watcom Symbol Loader Script - Compiler is not set to Watcom!\n");
		return;
	}
	
	//Get First program address which we will use to rebase it
	Base = MinEA();
	
	//Rebase to 0x0
	Message("Watcom Symbol Loader Script - Rebasing program to 0x0\n");
	RebaseProgram(-Base, MSF_SILENT);
	
	//Load the "Load DWARF File" plugin, RunPlugin takes the PLW filename
	RunPlugin("dwarf", 0);
	
	//Restore original base
	Message("Watcom Symbol Loader Script - Restoring original base of %X\n", Base);
	RebaseProgram(Base, MSF_SILENT);
}