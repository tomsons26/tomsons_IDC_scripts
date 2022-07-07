# vtable collector/namer script
# currently for VectorClass, DynamicVectorClass, TypeList, TClassFactory
# by tomsons26
# this parses a existing binary with these virtual tables
# builds a script that names these vtables in another binary with the same virtual tables
# note, before running this script or the produced script
# Class Informer or some other RTTI analysis and naming method must be ran
# as these scripts parse names in IDA to find the vtables
import hashlib

def print_vtable_list(t, a, c):
    n = GetTrueName(a);
    h = hashlib.md5(n).hexdigest()

    t.append('table_%s'%(h))
    
    print('    table_%s = ['%(h))
    # print real virtual table name
    print('        "%s",'%(n))
    # print out virtual names
    for i in range(0, c):
        n = GetTrueName(Dword(a + (i * 4)))
        print('        "%s",'%(n))
    print("    ]") 

def do_vtable_collection():
    # print namer function
    print(
"""def name_vtable(t):
    loc = LocByName(t[0]);
    if loc != BADADDR:
        #print("Found", t[0])
        i = 1
        while i < len(t):
            MakeName(Dword(loc + ((i * 4) - 4)), t[i])
            i = i + 1
    else:
        print("Can't find", t[0])
""")
    print('def name_virtuals():')

    vt_table = []
    # collect vtables
    valid_vc_name = ["??_7?$VectorClass", "??_7?$DynamicVectorClass", "??_7?$TypeList"]
    valid_cf_name = ["??_7?$TClassFactory"]

    for ea, name in idautils.Names():
        if any(s in name for s in valid_vc_name):
            print_vtable_list(vt_table, ea, 6)
        elif any(s in name for s in valid_cf_name):
            print_vtable_list(vt_table, ea, 5)
    
    # print out table of tables
    print('    list_table = [')
    for e in vt_table:
        print('        %s,' %(e))
    print("    ]") 
    
    #for e in vt_table:
    #    print("    name_vtable(%s)" %(e))
    
    # create a naming loop that we will use
    print(
"""    for e in list_table:
        name_vtable(e)
""")

    # print call to main function
    print('name_virtuals()')

do_vtable_collection()