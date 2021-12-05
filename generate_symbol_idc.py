#Symbol dump script
#by tomsons26
#Writes symbols to a runnable idc script
import idautils

bad_name = ["SEH_", "unknown_lib", "_SEH", "jpt_", "__cfltcvt", "__unwindfuncle"]

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
    #write out the header
    idc_file.write("#include <idc.idc>\n\nstatic main(void)\n{\n")

    for ea, name in idautils.Names():
        if Check_Name(name, specific):
            idc_file.write(format("    MakeName(0x%X, \"%s\");\n" % (ea, name)))

    #write function end
    idc_file.write("}\n")

#this is the main

# workarounds stupid bug that locks input cause of this dialog
ida_kernwin.hide_wait_box()
idc.set_ida_state(idc.IDA_STATUS_WAITING)

file_name = AskFile(1, "*.idc", "IDC File")
specific = AskStr("", "Type In string to filter.\nCase Sensitive!\nLeave black for all symbols.")

if file_name:
# workarounds stupid bug that locks input cause of this dialog
    ida_kernwin.show_wait_box("Processing IDB...")
    idc.set_ida_state(idc.IDA_STATUS_WORK)
    
    idc_file = file(file_name, "w")
    Write_IDC(idc_file, specific)
    idc_file.close()
    
# workarounds stupid bug that locks input cause of this dialog
    idc.set_ida_state(idc.IDA_STATUS_READY)
    ida_kernwin.hide_wait_box()
else:
    Message("No file!\n");
