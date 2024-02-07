def define_uncalled_functions():
    for addr, name in idautils.Names():
        flags = idc.GetFlags(addr)
        if idc.isCode(flags):
            MakeFunction(addr, BADADDR)

def GetName(name):
    dname = demangle_name(name, 0)
    if dname == None:
        dname = name
        
    return dname
    
def build_function_list():
    function_list = []
    for addr in idautils.Functions():
        start, end = list(idautils.Chunks(addr))[0]
        name = GetName(idc.GetFunctionName(addr))
        
        #stop at first lib, we passed game code
        if name == "__wcpp_2_undef_vfun__":
            break
        
        entry = {
            'name': name,
            'size': end - start 
        }
        function_list.append(entry)

    return function_list
    
def sort_method(list):
    return list['name']
    
define_uncalled_functions()
    
function_list = build_function_list()
#function_list.sort(key=sort_method)

for item in function_list:
        print('%s\t%s' %(item['name'], (item['size'])))