#SymbolList dump script
#by tomsons26
#Writes symbols to a runnable idc script
import idautils

bad_name = ["SEH_", "unknown_lib", "_SEH"]

def Check_Name(string, specific):

    if specific:
        if not specific in string:
            return False

    #we aren't printing specific names so check for bad names
    else:
        #check for symbol names that are are useless to dump
        if any(s in string for s in bad_name):
            return False
    
    #this is a good name
    return True

def Write_IDC(idc_file, specific):
    for ea, name in idautils.Names():
        if Check_Name(name, specific):
            idc_file.write(format("0x%X \"%s\"\n" % (ea, name)))

#this is the main
file_name = AskFile(1, "*.symlist", "symlist File")
specific = AskStr("", "Type In string to filter.\nCase Sensitive!\nLeave black for all symbols.")

if file_name:
    idc_file = file(file_name, "w")
    Write_IDC(idc_file, specific)
    idc_file.close()
else:
    Message("No file!\n");
