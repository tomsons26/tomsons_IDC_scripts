# ASM Hasher
# By tomsons26
# Hashes assembly of all functions in the IDB and outputs the hash list to a file
#
# TODO: revise to reduce special case handling, cleanup, speed improvements
#
# IMPORTANT!!: This requires IDA 7.4+ and iced_x86
# iced_x86 isn't available for Python 2 so this gets limited to 7.4+

import os.path

from iced_x86 import *
import re
import idautils
import hashlib
import time

from time import perf_counter
from timeit import timeit

allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

JUMP_OPERATORS = [
	Mnemonic.JA,  Mnemonic.JAE, Mnemonic.JB, Mnemonic.JBE, Mnemonic.JCXZ,  Mnemonic.JE,   Mnemonic.JECXZ,
	Mnemonic.JG,  Mnemonic.JGE, Mnemonic.JL, Mnemonic.JLE, Mnemonic.JMP,   Mnemonic.JMPE, Mnemonic.JNE,   Mnemonic.JNO,
	Mnemonic.JNP, Mnemonic.JNS, Mnemonic.JO, Mnemonic.JP,  Mnemonic.JRCXZ, Mnemonic.JS,   Mnemonic.JKNZD, Mnemonic.JKZD
]

COND_BRANCHES = [
	OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64
]

IMMEDIATES = [
	OpKind.IMMEDIATE8, OpKind.IMMEDIATE8_2ND, OpKind.IMMEDIATE16, OpKind.IMMEDIATE32, OpKind.IMMEDIATE32,
	OpKind.IMMEDIATE8TO16, OpKind.IMMEDIATE8TO32, OpKind.IMMEDIATE8TO64, OpKind.IMMEDIATE32TO64
]

ADDRESS_HOLDERS = [
	Mnemonic.PUSH, Mnemonic.POP,
	Mnemonic.NEG, Mnemonic.ADD, Mnemonic.SUB, Mnemonic.MUL, Mnemonic.IMUL,
	Mnemonic.MOV, Mnemonic.MOVZX, Mnemonic.MOVSX, Mnemonic.LEA,
	Mnemonic.CMP, Mnemonic.TEST, Mnemonic.AND, Mnemonic.OR, Mnemonic.XOR, Mnemonic.SETE,
	Mnemonic.SHL, Mnemonic.SHR,
	Mnemonic.INC, Mnemonic.DEC,
	Mnemonic.FLD, Mnemonic.FMUL, Mnemonic.FMULP, Mnemonic.FSUB, Mnemonic.FADD, Mnemonic.FCOMP, Mnemonic.FCOMPP,
	Mnemonic.FSTP, Mnemonic.FDIV, Mnemonic.FILD, Mnemonic.FCOM, Mnemonic.IDIV, Mnemonic.FDIVR, Mnemonic.FSUBR,
	Mnemonic.FST, Mnemonic.FIMUL,

	Mnemonic.LOOP, Mnemonic.LOOPE, Mnemonic.LOOPNE, # needs others
]

out_path = "D:\\Temp\\"
file_name = "hashlist"

list_file_path = out_path + file_name + ".txt"

class Instruction:
	def __init__(self, ip: int, mnemonic: int, opcode: str, operands: list, branch: int, function_start: int, has_label=False):
		self.ip = ip
		self.mnemonic = mnemonic
		self.opcode = opcode
		self.operands = operands
		self.branch = branch
		self.function_start = function_start
		self.has_label = has_label

	def __str__(self):
		string = f"\nlabel_{self.ip - self.function_start:06X}:\n" if self.has_label else ""
		string += f"{self.opcode} {','.join(self.operands)}"
		return string


def hex_to_int(string):
	return int(f"0x{string.replace('h', '')}", 16)

def get_demangled_name(name):
	dname = idc.demangle_name(name, 8)
	if dname == None:
		dname = name
	return dname

min_ea = ida_ida.inf_get_min_ea()
max_ea = ida_ida.inf_get_max_ea()

def is_address_in_binary(address):
   return min_ea <= address <= max_ea

keleven = 17391172068829961267

def _cycle(h, b):
	h |= 5
	h ^= b
	h *= h
	h ^= (h >> 32)
	h &= 0xffffffffffffffff
	return h

def _cycle_str(h, str):
	for c in str.encode():
		h = _cycle(h, c)
	return h

def get_immediate(instr, idx):
	if instr.op_kind(idx) in IMMEDIATES:
		return instr.immediate(idx)
	return 0

def hash_function(address, file):
	instructions = list()
	address_regex = re.compile("[A-Z0-9]+h(?=[^A-Z0-9]*?)")

	function = ida_funcs.get_func(address)
	function_start = function.start_ea
	function_bytes = ida_bytes.get_bytes(function.start_ea, function.end_ea - function.start_ea)

	decoder = Decoder(32, function_bytes, ip=function_start)
	formatter = Formatter(FormatterSyntax.MASM)
	# formatter.memory_size_options = MemorySizeOptions.ALWAYS

	#t = perf_counter()

	for instr in decoder:
		disasm = formatter.format(instr)

		parts = disasm.split(" ")
		opcode = parts[0]
		operands = " ".join(parts[1:]).split(",") if len(parts) > 1 else []

		#for o in disasm:
		#    print(o)
		#print('     end', hex(instr.ip), instr.op_count, get_immediate(instr, 0), get_immediate(instr, 1), get_immediate(instr, 2), get_immediate(instr, 3), get_immediate(instr, 4))

		branch = 0
		if instr.mnemonic != Mnemonic.CALL and instr.op0_kind in COND_BRANCHES:
			branch = instr.near_branch_target - function_start

		instructions.append(Instruction(instr.ip, instr.mnemonic, opcode, operands, branch, function_start))

	#print("Completed decode loop in", f'{perf_counter()-t:9.6f}s')

	#print(f"Hashing {function_start:08X}")
	t = perf_counter()

	for instr in instructions:
		if instr.mnemonic in JUMP_OPERATORS:
			try:
				jump_address_match = address_regex.search(instr.operands[0])

				if jump_address_match is None:
					continue

				jump_address = jump_address_match.group(0)
				jump_address_int = hex_to_int(jump_address)
				if not is_address_in_binary(jump_address_int):
					continue

				instr.operands[0] = instr.operands[0].replace(jump_address, f"label_{jump_address_int - function_start:06X}")
				#instr.branch = jump_address_int - function_start

				for dest_instr in instructions:
					if jump_address_int == dest_instr.ip:
						dest_instr.has_label = True
						break

			except:
				print(f"WARNING: Jump address not found. IP: {instr.ip:X}. {str(instr)}")
				continue

		elif instr.mnemonic == Mnemonic.CALL:
			try:
				call_address_match = address_regex.search(instr.operands[0])

				if call_address_match is None:
					continue

				call_address = call_address_match.group(0)
				call_address_int = hex_to_int(call_address)
				if not is_address_in_binary(call_address_int):
					continue

				instr.operands[0] = instr.operands[0].replace(call_address, "")

			except:
				print(f"WARNING: Call address not found. IP: {instr.ip:X}. {str(instr)}")
				continue

		elif instr.mnemonic in ADDRESS_HOLDERS:
			for i in range(len(instr.operands)):
				operand = instr.operands[i]
				address_match = address_regex.search(operand)
				if address_match is None:
					continue

				address_str = address_match.group(0)
				address_int = hex_to_int(address_str)
				if not is_address_in_binary(address_int):
					continue

				if address_str == operand:
					instr.operands[i] = f"offset"
				else:
					instr.operands[i] = operand.replace(address_str, "")
		else:
			for i in range(len(instr.operands)):
				operand = instr.operands[i]
				address_match = address_regex.search(operand)
				if address_match is None:
					continue

				address_str = address_match.group(0)
				address_int = hex_to_int(address_str)
				if not is_address_in_binary(address_int):
					continue

				print(f"WARNING: Dunno what to do with. IP: {instr.ip:X}. {str(instr)}")
				continue

			#print(f"WARNING: Dunno what to do with. IP: {instr.ip:X}. {str(instr)}")
			continue

	#print("Completed instructions loop 1 in", f'{perf_counter()-t:9.6f}s')

	#string = ""
	#for inst in instructions:
	#    string = string + str(inst)

	#comment out when dumping list or else will take forever
	#file.write(string + "\n")
	#return hashlib.sha1(string.encode()).hexdigest()
	#t = perf_counter()

	mh = keleven
	oh = keleven
	bh = keleven
	for inst in instructions:
		mh = _cycle(mh, inst.mnemonic)
		oh = _cycle_str(oh, str(inst.operands))
		bh = _cycle(bh, int(inst.branch))
		#print(hex(inst.branch))
	#print("Completed hash loop in", f'{perf_counter()-t:9.6f}s')
	return "%016X-%016X-%016X" % (mh, oh, bh)

LIST_HEADER = "TODO some prefix metadata maybe"

append_mode = False
if os.path.isfile(list_file_path):
	with open(list_file_path, "r") as f:
		contents = f.read()

	end_index = contents.rfind("END")
	append_mode = end_index != -1 and contents.startswith(ASM_HEADER)

	if append_mode:
		contents = contents[:end_index] + "\n\n"

with open(list_file_path, "w") as f:
	#if append_mode:
	#    f.write(contents)
	#else:
	#f.write(LIST_HEADER)

	hashes = list()

	#restore to dump singe
	#addr = here()
	#hashes.append(hash_function(addr, f) +" " + get_demangled_name(idc.get_func_name(addr)))

	#restore to dump list
	num = len(list(idautils.Functions()))
	t = perf_counter()
	for i, addr in enumerate(idautils.Functions()):
		ida_kernwin.replace_wait_box("Processing function %08X %d/%d" % (addr, i, num))
		hashes.append(hash_function(addr, f) + " //" + get_demangled_name(idc.get_func_name(addr)))

	print("Completed hashing in", f'{perf_counter()-t:9.6f}s')

	for ha in hashes:
		f.write(ha + "\n")
