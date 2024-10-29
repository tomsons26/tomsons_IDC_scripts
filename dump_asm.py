#by tomsons26
#thank fuck for https://github.com/tmr232/idapython/blob/master/examples/ex_actions.py

import idc
import idaapi
import idautils
import ida_nalt
import ida_idaapi
import ida_bytes
import ida_funcs
import ida_ida
import ida_ua
import ida_name
import ida_xref
import ida_kernwin

ASM_DUMP_PATH = "D:\\Temp\\"

# .asm is appended
PROJECT_NAME = "project"
TARGET_NAME = "target"

def clear_output():
	form = idaapi.find_widget("Output window")
	idaapi.activate_widget(form, True)
	idaapi.process_ui_action("msglist:Clear")

class FunctionSizeHash:

	def __init__(self, name, size, ihash, vhash, bhash, addr, ugh):
		self.name = name
		self.size = size
		self.ihash = ihash
		self.vhash = vhash
		self.bhash = bhash
		self.addr = addr
		self.ugh = ugh

#	def __repr__(self):
#		return '%s\t%s\t0x%08X' % (self.name, self.size, self.hash, self.addr)


def define_uncalled_functions():
	for addr, name in idautils.Names():
		flags = ida_bytes.get_full_flags(addr)
		if ida_bytes.is_code(flags):
			ida_funcs.add_func(addr)

def GetName(name):
	dname = idc.demangle_name(name, 8)
	if dname == None:
		dname = name

	return dname

def name_ex(From, ea):
	return idc.get_name(ea, idc.GN_LOCAL)

def xref_count(addr):
	i = 0
	xrefs = idaapi.xrefblk_t()
	if xrefs.first_to(addr, 0):
		i +=1
		while xrefs.next_to():
			i += 1
	return i

keleven = 17391172068829961267

def _cycle(h, b):
	h |= 5
	h ^= b
	h *= h
	h ^= (h >> 32)
	h &= 0xffffffffffffffff
	return h

def instruction_hash(addr):
	h = keleven
	for ea in idautils.FuncItems(addr):
		h = _cycle(h, idc.get_wide_byte(ea))
		# go over all additional bytes of any instruction
		for i in range(ea + 1, ea + idc.get_item_size(ea)):
			h = _cycle(h, idc.get_wide_byte(i))
	return h

def identity_hashOLD(addr):
	h = keleven
	for ea in idautils.FuncItems(addr):
		h = _cycle(h, idc.get_wide_byte(ea))
		# does nothing?
		# skip additional bytes of any instruction that contains an offset in it
		#if idautils.CodeRefsFrom(ea, False) or idautils.DataRefsFrom(ea):
		#	print "bailing on ", hex(ea), "\n"
		#	continue
		#for i in range(ea + 1, ea + idc.get_item_size(ea)):
		#	h = _cycle(h, idc.get_wide_byte(i))
	if h == keleven:
		#print "Warning couldn't hash ", value_as_hex_str(addr), "\n"
		return 0x0000000000000000

	return h

def identity_hash(addr):
	h = keleven
	insn = ida_ua.insn_t()
	for ea in idautils.FuncItems(addr):
		length = ida_ua.decode_insn(insn, ea)
		if length == 0:
			#print "failed decoding //", value_as_hex_str(ea)
			continue
		h = _cycle(h, insn.itype)
		if h == keleven:
			#print "Warning couldn't hash ", value_as_hex_str(addr), "\n"
			return 0x0000000000000000

	return h

def value_as_hex_str(v):
	return "0x%016X" % v

#old and flawed, using immediate_hash now
def value_hash(addr):
	h = keleven
	insn = ida_ua.insn_t()

	for ea in idautils.FuncItems(addr):
		length = ida_ua.decode_insn(insn, ea)
		if length == 0:
			#print "failed decoding //", value_as_hex_str(ea)
			continue
		for c, v in enumerate(insn.ops):

			#debug
			#print hex(ea), "type ", v.type, " dtype", v.dtype, "//flags ", get_full_flags(ea)

			#skip no operands
			if v.type == idaapi.o_void:
				#print "     skipping void at //", value_as_hex_str(ea)
				break

			#skip mem refs
			if v.type == idaapi.o_mem:
				#print "     skipping mem at //", value_as_hex_str(ea)
				continue

			#skip calls
			if v.type == idaapi.o_far or v.type == idaapi.o_near:
				#print "     breaking call at //", value_as_hex_str(ea)
				break


			# useless cause is_loaded covers it?
			#
			# skip additional bytes of any instruction that contains an offset in it
			# this code is a disaster
			#refs1 = list(idautils.DataRefsFrom(ea))
			#refs2 = list(idautils.CodeRefsFrom(ea, False))
			#if len(refs1) != 0 or len(refs2) != 0:
			#if len(refs1) != 0:
			#trying this tho likely slow
			#xref = list(XrefsFrom(ea, ida_xref.XREF_DATA))
			#if xref:
				#x = xref[0]
				#print(hex(ea), x.type, XrefTypeName(x.type), 'from', hex(x.frm), 'to', hex(x.to))
				#boo data reference
				#if x.type == ida_xref.dr_O:
					#print "//skipping xref at ", value_as_hex_str(ea)
					#continue

			if v.type == idaapi.o_imm:
				value = idc.get_operand_value(ea, c)
				val_ea = ea + v.offb + v.offo

				fixup = idc.get_fixup_target_type(val_ea)
				#print fixup
				if fixup == idc.FIXUP_OFF32:
					#print "     skipping address with fixup value", value, "at //", value_as_hex_str(val_ea)
					continue

				# we only want intermediate values, no memory addresses
				flags = idc.get_full_flags(ea);
				#obj bug workaround
				if value != 0 and value != 0xFFFFFFFF:
					#if is_loaded(value) or isRef(flags): #skips nonaddresses in oobj....
					if idc.is_loaded(value):
						#print "     skipping address value", value, "at //", value_as_hex_str(val_ea)
						continue

				#debug
				#print "hashing value", value, "at //", value_as_hex_str(val_ea)
				h = _cycle(h, value)

	#nothing to hash?
	if h == keleven:
		#print "Warning couldn't hash ", value_as_hex_str(addr), "\n"
		return 0x0000000000000000

	return h

#print value_as_hex_str(value_hash(ScreenEA()))

def immediate_hash(addr):
	h = keleven
	insn = ida_ua.insn_t()

	for ea in idautils.FuncItems(addr):
		length = ida_ua.decode_insn(insn, ea)
		if length == 0:
			#print "failed decoding //", value_as_hex_str(ea)
			continue

		for c, v in enumerate(insn.ops):

			#no operand
			if v.type == idaapi.o_void:
				#print "     skipping mem at //", value_as_hex_str(ea)
				continue

			#skip calls
			if v.type == idaapi.o_far or v.type == idaapi.o_near:
				#print "     breaking call at //", value_as_hex_str(ea)
				break

			#skip mem refs
			if v.type == idaapi.o_mem:
				#print "     skipping mem at //", value_as_hex_str(ea)
				continue

			#has no immediate
			value = ida_ua.get_immvals(ea, c)
			if len(value) == 0:
				continue

			#print hex(ea), "type ", v.type, " dtype", v.dtype, "//flags ", get_full_flags(ea)

			val_ea = ea + v.offb + v.offo

			fixup = idc.get_fixup_target_type(val_ea)
			#print fixup
			if fixup == idc.FIXUP_OFF32:
				#print "     skipping address with fixup value", value, "at //", value_as_hex_str(val_ea)
				continue

			dw = idc.get_wide_dword(val_ea)
			if ida_bytes.is_loaded(dw) and ida_bytes.is_data(ida_bytes.get_full_flags(dw)):
				#print "     skipping data", value, "at //", value_as_hex_str(val_ea)
				continue

			#debug
			#print "hashing value", value, "at //", value_as_hex_str(val_ea)
			h = _cycle(h, value[0])

	if h == keleven:
		#print "Warning couldn't hash ", value_as_hex_str(addr), "\n"
		return 0x0000000000000000

	return h

#print value_as_hex_str(immediate_hash(ScreenEA()))

#check with if mnem in jmp_ins_list:
#jmp_ins_list = ["jmp","jc","jnc","jz","jnz","js","jns","jo","jno","jp",
#				"jpe","jnp","jpo","ja","jnbe","jae","jnb","jb","jnae","jbe",
#				"jna","je","jne","jg","jnle","jge","jnl","jl","jnge","jle","jng"]

from ida_allins import *

cond_jumps = (
	idaapi.NN_ja,
	idaapi.NN_jae,
	idaapi.NN_jb,
	idaapi.NN_jbe,
	idaapi.NN_jc,
	idaapi.NN_jcxz,
	idaapi.NN_jecxz,
	idaapi.NN_jrcxz,
	idaapi.NN_je,
	idaapi.NN_jg,
	idaapi.NN_jge,
	idaapi.NN_jl,
	idaapi.NN_jle,
	idaapi.NN_jna,
	idaapi.NN_jnae,
	idaapi.NN_jnb,
	idaapi.NN_jnbe,
	idaapi.NN_jnc,
	idaapi.NN_jne,
	idaapi.NN_jng,
	idaapi.NN_jnge,
	idaapi.NN_jnl,
	idaapi.NN_jnle,
	idaapi.NN_jno,
	idaapi.NN_jnp,
	idaapi.NN_jns,
	idaapi.NN_jnz,
	idaapi.NN_jo,
	idaapi.NN_jp,
	idaapi.NN_jpe,
	idaapi.NN_jpo,
	idaapi.NN_js,
	idaapi.NN_jz,
	idaapi.NN_loopw,
	idaapi.NN_loop,
	idaapi.NN_loopd,
	idaapi.NN_loopq,
	idaapi.NN_loopwe,
	idaapi.NN_loope,
	idaapi.NN_loopde,
	idaapi.NN_loopqe,
	idaapi.NN_loopwne,
	idaapi.NN_loopne,
	idaapi.NN_loopdne,
	idaapi.NN_loopqne
)

jumps = (
	idaapi.NN_jmp,
	idaapi.NN_jmpfi,
	idaapi.NN_jmpni,
	idaapi.NN_jmpshort
)

branch_log = []

def branch_hash(addr, log):
	h = keleven
	insn = ida_ua.insn_t()
	fstart = idc.get_func_attr(addr, idc.FUNCATTR_START)
	for ea in idautils.FuncItems(addr):
		#mnem = idc.print_insn_mnem(ea)
		#if mnem in jmp_ins_list:
		ida_ua.decode_insn(insn, ea)
		if insn.itype in cond_jumps or insn.itype in jumps:
			#length = ida_ua.decode_insn(insn, ea)
			#if length == 0:
				#print "failed decoding //", value_as_hex_str(ea)
			#	continue
			#print hex(insn.cs), hex(insn.ip), hex(insn.ea), insn.itype, insn.size
			#print hex(insn.ea - fstart)

			size = idc.get_item_size(ea);

			#if mnem == "jmp":
			if insn.itype in jumps:
				if size > 4:
					# only hash the first two bytes
					size = 1;
				elif size > 5:
					# ignore switch addresses
					size = 2;

			for i in range(ea, ea + size):
				h = _cycle(h, idc.get_wide_byte(i))
				if log:
					branch_log.append('%08X %s' % (ea - fstart, value_as_hex_str(h)))
		#else:
		#	print "nope", hex(ea)[0:-1]

	if h == keleven:
		#print "Warning couldn't hash ", value_as_hex_str(addr), "\n"
		return 0x0000000000000000

	return h

#print branch_hash(here(), 0)

def build_function_list(funcs):
	function_list = []
	for addr in funcs:
		#skip extern segments that are usually in objs
		#if idc.get_segm_attr(addr, idc.SEGATTR_TYPE) == idaapi.SEG_XTRN:
		#	continue;
		#
		#skip obj comdats
		#if "COMDAT" in idc.get_segm_name(addr):
		#	continue;

		start, end = list(idautils.Chunks(addr))[0]
		name = GetName(idc.get_func_name(addr))
		#stop at first lib, we passed game code
		#if name == "__wcpp_2_undef_vfun__":
		#	break

		#h = hash(hasher.calculate(start))
		ih = identity_hash(start)
		vh = immediate_hash(start)
		bh = branch_hash(start, 0)
		#convert to hex string, strip 0x and L, make upper case
		ihs = value_as_hex_str(ih)
		vhs = value_as_hex_str(vh)
		bhs = value_as_hex_str(bh)

		cmt = idc.get_func_cmt(start, 1)

		ugh = 0
		if cmt == 'fixed diff':
			ugh = 1

		entry = FunctionSizeHash(name, end - start, ihs, vhs, bhs, start, ugh)

		function_list.append(entry)

	return function_list

def sort_method(list):
	return list.name


# wrapper for context class so i don't have to write one for every single action
class ctx_wrapper(idaapi.action_handler_t):
	def __init__(self, action_function):
		idaapi.action_handler_t.__init__(self)
		self.action_function = action_function

	def activate(self, ctx):
		self.action_function(ctx)
		return 1

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

#ida is buggy with listing option changing, doesn't always restore them...
#we don't want any strange modifications for the listing
#representation in our work idbs
def is_cnc():
	if ida_nalt.get_root_filename() == "C&C95.EXE":
		return 1

	if ida_nalt.get_root_filename() == "sole.exe":
		return 1

	if ida_nalt.get_root_filename() == "redalert.exe":
		return 1

	if "ra95" in ida_nalt.get_root_filename():
		return 1

	return 0

def get_stack_offset_str(v):
	v = (v ^ 0x80000000) - 0x80000000
	sign = "?"
	if v > 0:
		sign = "+"
	else:
		sign = "-"
		v = abs(v)

	return sign + "%Xh" % v

#prob will rework as needed as above is extensive
def format_op(addr, num):
	type = idc.get_operand_type(addr, num)
	op = idc.print_operand(addr, num)
	val = idc.get_operand_value(addr, num)

	if op == "":
		return op

	pos = op.find("dword ptr ")
	if pos != -1:
		op = op[0:pos] + op[pos + 10:]

	#pos = op.find("offset ")
	#if pos == 0:
	#	op = op[pos + 7:]

	pos = op.find("ds:")
	if pos != -1:
		op = op[0:pos] + op[pos + 3:]

	#if type == 2:
	#	pos = op.find("[")
	#	if pos == -1:
	#		op = "[" + op + "]"

	# attempt to remove op_num hacks
	elif type == idaapi.o_displ:
		ptr = op.find("(")
		#don't touch obj data refs
		if ptr == -1:
			rstart = op.find("[")
			if rstart != -1:
				rfound = 0
				#print hex(addr), op
				rend = op.find("+")
				if rend != -1:
					rfound = 1
				else:
					rend = op.find("-")
					if rend != -1:
						rfound = 2

				if rfound != 0:
					reg = op[rstart+1:rend]
					stack = get_stack_offset_str(val)
					op = "[" + reg + stack + "]"

	elif type == idaapi.o_imm:
		usehex = 1
		pos = op.find("offset")
		if pos >= 0:
			op = "offset " + op
			usehex = 0

		pos = op.find("asc")
		if pos != -1:
			l = idc.generate_disasm_line(addr, 0)
			pos = l.find(";")
			op = "offset ascii " + l[pos:]
			usehex= 0

		if usehex:
			op = "%Xh" % val

	"""
	#ugh
	elif type == 4:
		pos = op.find("[")
		if pos >= 0:
			print "pos %s" % pos
			idx = pos - 1
			var = ""
			while idx >= 0:
				ch = op[idx:idx + 1]
				print "ch %s" % ch
				if ch == " ":
					break
				var = ch + var
				print "pos %s" % var
				idx = idx - 1
			if var != "":
				op = op[0:idx + 1] + "[" + var + "+" + op[pos + 1:]
	"""

	return op

def build_op_dtype_line(addr):
	line = ""
	insn = ida_ua.insn_t()
	length = ida_ua.decode_insn(insn, addr)

	# type is "Operand types" https://hex-rays.com/products/ida/support/sdkdoc/group__o__.html
	# dtype is "Operand value types" https://hex-rays.com/products/ida/support/sdkdoc/group__dt__.html
	if length != 0:
		line = "%02d %02d %02d %02d %02d %02d %02d %02d" % (insn.ops[0].dtype, insn.ops[1].dtype, insn.ops[2].dtype, insn.ops[3].dtype, insn.ops[0].type, insn.ops[1].type, insn.ops[2].type, insn.ops[3].type)

	return line

import time
from timeit import default_timer as timer
def dump_func_asm(ea):
	listing = []

	del branch_log[:]

	if idaapi.IDA_SDK_VERSION <= 700:
		minEA = idc.MinEA()
		maxEA = idc.MaxEA()
	else:
		minEA = ida_ida.inf_get_min_ea()
		maxEA = ida_ida.inf_get_max_ea()

	fstart = idc.get_func_attr(ea, idc.FUNCATTR_START)
	fend = idc.get_func_attr(ea, idc.FUNCATTR_END)

	fname = GetName(idc.get_func_name(fstart))

	t = timer()
	ih = identity_hash(fstart)
	print("Completed identity_hash in ", timer() - t, "seconds")
	t = timer()
	vh = immediate_hash(fstart)
	print("Completed immediate_hash in", timer() - t, "seconds")
	t = timer()
	bh = branch_hash(fstart, 1)
	print("Completed branch_hash in   ", timer() - t, "seconds")

	#convert to hex string, strip 0x and L, make upper case
	ihs = value_as_hex_str(ih)
	vhs = value_as_hex_str(vh)
	bhs = value_as_hex_str(bh)

	cmt = idc.get_func_cmt(fstart, 1)

	ugh = 0
	if cmt == 'fixed diff':
		ugh = 1

	entry = FunctionSizeHash(fname, fend - fstart, ihs, vhs, bhs, fstart, ugh)
	listing.append('%s-%s-%s\t//%s\t//%d\n' % (entry.ihash, entry.vhash, entry.bhash, entry.name, entry.size))

	fname = idc.get_func_name(fstart)

	listing.append("section .text\n")
	listing.append("global %s\n" % fname)
	listing.append("%s:\n" % fname)

	addr = fstart
	while addr != idc.BADADDR:
		if addr != fstart:
			name = name_ex(addr, addr)

			#ignore debug_info labels in objs
			#if name != "" and ida_xref.get_first_fcref_to(addr) == -1:
			#if name != "" and ida_xref.get_first_dref_to(addr) == 0xFFFFFFFF:
			if name != "" and ida_xref.get_first_fcref_from(addr) != 0xFFFFFFFF or ida_xref.get_first_fcref_to(addr) != 0xFFFFFFFF:
				#we want to keep our labels
				if not name.startswith("loc_"):
					listing.append("%s:" % name)
				else:
					listing.append("loc_%X:" % addr)


		op0Type = idc.get_operand_type(addr, 0)
		op1Type = idc.get_operand_type(addr, 1)
		op2Type = idc.get_operand_type(addr, 2)

		"""
		#horrible hack, trying currently to properly parse ops
		op0 = 0
		op1 = 0
		if op0Type == idaapi.o_phrase or op0Type == idaapi.o_displ:
			val = idc.get_operand_value(addr, 0)
			if val >= minEA and val <= maxEA:
				pass
			else:
				op0 = idc.op_num(addr, 0)

		if op1Type == idaapi.o_phrase or op1Type == idaapi.o_displ:
			val = idc.get_operand_value(addr, 1)
			if val >= minEA and val <= maxEA:
				pass
			else:
				op0 = idc.op_num(addr, 1)
		"""

		line = idc.generate_disasm_line(addr, 0)
		mnem = idc.print_insn_mnem(addr)

		oper0 = format_op(addr, 0)
		oper1 = format_op(addr, 1)
		oper2 = format_op(addr, 2)

		#if mnem == "call":
		#	if op0Type >= idaapi.o_imm and op0Type <= idaapi.o_near:
		#		if oper0.find("_") != 0:
		#			oper0 = "_" + oper0

		if oper0 == "" and oper1 == "" and oper2 == "":
			if line.find(mnem) != 0:
				mnem = line
			line = "%-8s" % (mnem)
		elif oper2 == "":
			if oper1 == "":
				line = "%-7s %s" % (mnem, oper0)
			elif oper0 == "":
				line = "%-7s %s" % (mnem, oper1)
			else:
				line = "%-7s %s, %s" % (mnem, oper0, oper1)
		else:
			line = "%-7s %s, %s, %s" % (mnem, oper0, oper1, oper2)

		#add a new line after calls and branches
		if op0Type == idaapi.o_near or op0Type == idaapi.o_far or mnem == "call":
			line = line + "\n"

		listing.append("%08X:   %s   %s" % (addr - fstart, build_op_dtype_line(addr), line))
		#listing.append("         %s" % (line))

		"""
		#horrible hack, trying curently to properly parse ops
		#if op0:
			#idc.op_stkvar(addr, 0)
		#if op1:
			#idc.op_stkvar(addr, 1)
		"""

		addr = idc.next_head(addr, fend)

	return listing

#l = dump_func_asm(ScreenEA())
#for item in l:
#	print "%s" % (item)

def dump_func(ctx, name, addr, cnc):
	file = ASM_DUMP_PATH + name + ".asm"

	#old
	#fstart = idc.get_func_attr(addr, idc.FUNCATTR_START)
	#fend = idc.get_func_attr(addr, idc.FUNCATTR_END)

	#these are buggy..
	#cnc idb already set up, don't mess with it
	#if cnc == 0:
	#	#we want relative offsets, no prefixes and no comments
	#	SetLongPrm(INF_PREFFLAG, PREF_FNCOFF)
	#	SetLongPrm(INF_CMTFLAG, SW_NOCMT)
	#	SetLongPrm(INF_OUTFLAGS, ~OFLG_SHOW_PREF)
	#	SetLongPrm(INF_OUTFLAGS, ~OFLG_PREF_SEG)

	#idc.gen_file(idc.OFILE_LST, file, fstart, fend, 0)
	#idc.gen_file(idc.OFILE_ASM, file, fstart, fend, 0)

	#if cnc == 0:
	#	#restore original flags
	#	SetLongPrm(INF_PREFFLAG, ~PREF_FNCOFF)
	#	SetLongPrm(INF_CMTFLAG, ~SW_NOCMT)
	#	SetLongPrm(INF_OUTFLAGS, OFLG_SHOW_PREF)
	#	SetLongPrm(INF_OUTFLAGS, OFLG_PREF_SEG)

	#new using modified disassembly
	f = open(file, "w")
	l = dump_func_asm(addr)

	for item in l:
		f.write(item + "\n")

	f.write("\n")

	for item in branch_log:
		f.write(item + "\n")

	f.close()

	print("Dumped Assembly to " + file)

def dump_func_list(ctx, sorted):

	define_uncalled_functions()

	clear_output()

	function_list = build_function_list(idautils.Functions())

	if sorted:
		function_list.sort(key=sort_method)

	for item in function_list:
		#print('%s\t//%s\t//%s\t//%d' % (item.ihash, item.vhash, item.name, item.size))
		extra = ''
		if item.ugh:
			extra = '|FIXEDDIFF'

		print('%s-%s-%s\t//%s\t//%d|%d%s' % (item.ihash, item.vhash, item.bhash, item.name, item.size, xref_count(item.addr), extra))

def dump_select_func_list(ctx):

	clear_output()

	function_list = []

	funcs = []
	# fill address array
	for pfn_idx in ctx.chooser_selection:
		pfn = ida_funcs.getn_func(pfn_idx)
		if pfn:
			funcs.append(pfn.start_ea)

	function_list = build_function_list(funcs);

	for item in function_list:
		#print('%s\t//%s\t//%s\t//%d' % (item.ihash, item.vhash, item.name, item.size))
		print('%s-%s-%s|%d\t//%s\t//%d' % (item.ihash, item.vhash, item.bhash, xref_count(item.addr), item.name, item.size))

def dump_project_asm(ctx):
	dump_func(ctx, PROJECT_NAME, idc.get_screen_ea(), is_cnc())

def dump_target_asm(ctx):
	dump_func(ctx, TARGET_NAME, idc.get_screen_ea(), is_cnc())

def dump_list(ctx):
	dump_func_list(ctx, 0)

def dump_sorted_list(ctx):
	dump_func_list(ctx, 1)

def no_op(ctx):
	return

# for the sake of knowing its active, appears as a text button next analyze buttons
ACTION_DMP1 = "asmdumpplugin:dmp1"
ACTION_DMP2 = "asmdumpplugin:dmp2"
ACTION_DMP3 = "asmdumpplugin:dmp3"
ACTION_DMP4 = "asmdumpplugin:dmp4"
ACTION_DMP5 = "asmdumpplugin:dmp5"

def asm_dumper_init():
	if idaapi.register_action(idaapi.action_desc_t(
			ACTION_DMP1,
			"Dump Project ASM",
			ctx_wrapper(dump_project_asm),
			None,
			"",
			-1,
			ida_kernwin.ADF_NO_UNDO
			)):

		# describe the action
		irraction_desc = idaapi.action_desc_t(
			ACTION_DMP2,
			"Dump Target ASM",
			ctx_wrapper(dump_target_asm),
			None,
			"",
			-1,
			ida_kernwin.ADF_NO_UNDO
		)
		assert idaapi.register_action(irraction_desc), "Action registration failed"

		irraction_desc = idaapi.action_desc_t(
			ACTION_DMP3,
			"Dump Func List",
			ctx_wrapper(dump_list),
			None,
			"",
			-1,
			ida_kernwin.ADF_NO_UNDO
		)
		assert idaapi.register_action(irraction_desc), "Action registration failed"

		irraction_desc = idaapi.action_desc_t(
			ACTION_DMP4,
			"Dump Sorted Func List",
			ctx_wrapper(dump_sorted_list),
			None,
			"",
			-1,
			ida_kernwin.ADF_NO_UNDO
		)
		assert idaapi.register_action(irraction_desc), "Action registration failed"

		irraction_desc = idaapi.action_desc_t(
			ACTION_DMP5,
			"Dump Select Func List",
			ctx_wrapper(dump_select_func_list),
			None,
			"",
			-1,
			ida_kernwin.ADF_NO_UNDO
		)
		assert idaapi.register_action(irraction_desc), "Action registration failed"

		print("Actions registered. Attaching to menu.")

		# Insert the action in a toolbar
		if idaapi.attach_action_to_toolbar("AnalysisToolBar", ACTION_DMP1):
			print("Attached to toolbar.")
		else:
			print("Failed attaching to toolbar.")

		# Insert the action in a toolbar
		if idaapi.attach_action_to_toolbar("AnalysisToolBar", ACTION_DMP2):
			print("Attached to toolbar.")
		else:
			print("Failed attaching to toolbar.")

		# Insert the action in a toolbar
		if idaapi.attach_action_to_toolbar("AnalysisToolBar", ACTION_DMP3):
			print("Attached to toolbar.")
		else:
			print("Failed attaching to toolbar.")

		# Insert the action in a toolbar
		if idaapi.attach_action_to_toolbar("AnalysisToolBar", ACTION_DMP4):
			print("Attached to toolbar.")
		else:
			print("Failed attaching to toolbar.")

		# Insert the action in a toolbar
		if idaapi.attach_action_to_toolbar("AnalysisToolBar", ACTION_DMP5):
			print("Attached to toolbar.")
		else:
			print("Failed attaching to toolbar.")

		if idc.get_segm_end(ida_ida.inf_get_min_ea()) >= 0x006C0000:
			# assume binary is too large to handle it currently, disable full function list buttons
			idaapi.unregister_action(ACTION_DMP3)
			idaapi.unregister_action(ACTION_DMP4)

def asm_dumper_term():
	# No need to call detach_action_from_menu(); it'll be
	# done automatically on destruction of the action.
	if idaapi.unregister_action(ACTION_DMP1):
		idaapi.unregister_action(ACTION_DMP2)
		idaapi.unregister_action(ACTION_DMP3)
		idaapi.unregister_action(ACTION_DMP4)
		idaapi.unregister_action(ACTION_DMP5)
	else:
		print("Failed to unregister action.")

class asm_dumper_t(idaapi.plugin_t):
	#flags = idaapi.PLUGIN_FIX
	flags = 0
	comment = "ASM dumper script"
	help = ""
	wanted_name = "ASM Dumper Script"
	wanted_hotkey = ""

	def init(self):
		print("Registering ASM Dumper.")
		asm_dumper_init()
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		pass

	def term(self):
		print("Unregistering ASM Dumper.")
		asm_dumper_term()

def PLUGIN_ENTRY():
	return asm_dumper_t()
