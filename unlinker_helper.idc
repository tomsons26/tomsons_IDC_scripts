#include <idc.idc>

//Unlinker Helper script
//by tomsons26
//Prints basic info needed for the Unlinker INI's to IDA Output Window

//PROBABLY_TODO
//Make it segment sensetive,
//SegName(ea) returns
//if .text use function format,
//if .rdata use rdata format,
//if .data use data format.

static main()
{
	//Prettely formated magic automatic type definitions :D
	auto
		cursor,
		function_name,
		function_address,
		file_address,
		function_size;
	
	//Get current cursor location
	cursor = ScreenEA();
	
	//Get function name at current cursor location
	function_name = GetFunctionName(cursor);

	//Get current Function start address
	function_address = GetFchunkAttr(cursor,FUNCATTR_START);
	
	//Get current function file address
	file_address = (GetFchunkAttr(cursor,FUNCATTR_START)-0x00400000);
	
	//Get current function size
	function_size = GetFchunkAttr(cursor,FUNCATTR_END)-GetFchunkAttr(cursor,FUNCATTR_START);

	//Print gathered info to output
	Message("[%s]\n",function_name);
	Message("Address=%Xh\n",function_address);
	Message("FileAddress=%Xh\n",file_address);
	Message("Size=%Xh\n",function_size);	
}