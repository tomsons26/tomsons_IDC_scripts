# Loads linker map
# by tomsons26
#
# Currently supports only MSVC VS6? Linker Map
#
# TODO:
# Watcom, Borland
# refactor so line processing is its own thing

import re
import ida_name
#import idc
#import idaapi

entries_found = False
listing = []
flist = {}
falist = list()

class FunctionData:
    def __init__(self, name, address, object):
        self.name = name
        self.address = address
        self.object = object
 
def set_symbol_name(Identifier, RVA):
    #if get_name(RVA)[:3] == "sub":
    ida_name.set_name(RVA, Identifier, ida_name.SN_FORCE)

def sort_list(e):
  return e.address

def sort_rva_list(e):
  return int(e)

def parse_line(line):
    #Message("parsing\n")
    m = re.match("([-.0-9]+:[0-9a-f]+).......([^\s]+)\s*([0-9a-f]+).....([^\s]+)\s*", line.strip(), re.IGNORECASE)
    if m is not None:
        Segment = m.group(0)[0:4]
        Address = m.group(1)
        Identifier = m.group(2)
        RVA = m.group(3)
        Object = m.group(4)
        RVAA = int(RVA[0:8], 16)

        #DName = Demangle(Identifier, INF_SHORT_DN)
        #if DName is None:
        #    DName = Identifier
        #print Address, Identifier

        # need to keep track of which are functions, usually in segment 1
        if Segment == "0001":
            falist.append(RVAA)
            #ida_funcs.add_func(RVAA)
        set_symbol_name(Identifier, RVAA)
        # comment what object it's from
        MakeComm(RVAA, "obj:" + Object)

        #print("%s\t%s\t0x%08X" % (DName, Object, RVAA))
        #listing.append("%s\t%s\t0x%08X" % (DName, Object, RVAA))
        #flist[RVAA] = FunctionData(DName, RVAA, Object)

def process_line(line):
    global entries_found
    if entries_found:
        parse_line(line)
    else:
        l = line.split()
        if len(l) >= 4 and l[0] == "Address":
            Message("block found\n")
            entries_found = True
     
fname = AskFile(0, "*.map", "Linker Map File")
if fname:
    msg("Opening map file\n")
    with open(fname, "r") as mapf:
        #Message("Opened")
        for line in mapf:
            process_line(line)

        # flag all functions as such
        if len(falist):
            # better results are yealded if functions are set in revers order bottom to top
            # otherwise ida declares a lot of stuff wrongly as tail functions 
            falist.sort(key=None, reverse=True)
            # set everything that's a function as a function
            for rva in falist:                    
                ida_funcs.add_func(rva)
                #print(hex(rva))

        mapf.close()
        
    #f = open(fname + "dem", "w")

    #for item in listing:
    #    f.write(item + "\n")

    #f.write("Module List\n")

    #for k in sorted(flist):
    #    e = flist[k]
    #    f.write("0x%08X\t%s\t%s\n" % (e.address, e.name, e.object))

    #f.close()
else:
    Message("No file selected!\n")
