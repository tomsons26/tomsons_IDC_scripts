//
//Bad name filter
//by tomsons26
//Filters out IDA generated names
//Intended to be used with other scripts
//

#include <idc.idc>

static Check_For_Bad_Name(String)
{
	auto s;

	if (String == "")
	{
		return 1;
	}

	s = substr(String, 0, 4);
	if (s == "sub_" ||
		s == "SEH_" ||
		s == "unk_" ||
		s == "loc_" ||
		s == "off_" ||
		s == "flt_" ||
		s == "dbl_" ||
		s == "asc_")
	{
		return 1;
	}

	s = substr(String, 0, 5);
	if (s == "byte_" ||
		s == "word_" ||
		s == "stru_")
	{
		return 1;
	}

	s = substr(String, 0, 6);
	if (s == "dword_" ||
		s == "__imp_" ||
		s == "j_sub_" ||
		s == "j_SEH_" ||
		s == "qword_")
	{
		return 1;
	}

	s = substr(String, 0, 7);
	if (s == "locret_" ||
		s == "__imp__")
	{
		return 1;
	}

	s = substr(String, 0, 8);
	if (s == "nullsub_" ||
		s == "j_nullsu" ||
		s == "xmmword_")
	{
		return 1;
	}

	s = substr(String, 0, 16);
	if (s == "unknown_libname_" ||
		s == "j_unknown_libnam" ||
		s == "__IMPORT_DESCRIP")
	{
		return 1;
	}

	return 0;
}