// Wrapper for GetString to make the code easier to read
// Get the function name from the Operand Value
static Get_Name(address)
{
    return GetString(GetOperandValue(address, 0), -1, 0);
}

// wrapper function to simply checking code
static String_Is_Present(check, string)
{
    if (strstr(check, string) != -1) {
        return 1;
    }
    return 0;
}

//MakeNameEx wrapper to make code easier to read
static Rename_Function(address, new_name)
{
    // Rename the function setting the name as public and replacing invalid chars with _
    if (MakeNameEx(address, new_name, SN_PUBLIC | SN_NOCHECK | SN_NOWARN) != 0) {
        return 1;
    }
    return 0;
}

static Is_Unamed_Function(address)
{
    if (String_Is_Present(GetFunctionName(address), "sub_")) {
        return 1;
    }
    return 0;
}


static Is_String_Pointer(address)
{
    if (String_Is_Present(GetOpnd(address, 0), "asc_")) {
        return 1;
    }
    return 0;
}