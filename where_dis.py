# Where Dis
# by tomsons26
#
# Adds the ability to check what module address relates to
#	to do this it uses a premade list, list is a text file in this format
#	(0x00563D10, 0x00564840, "movies.cpp")
#	list can have comments prefixing with #
#
# The option to use it shows up in rightclick menu of the disassembly view
#	'WhereDis' where dis'es
#	'Reload WhereDis' reloads the list
#	'Debug WhereDis' checks for duplicates in list
#
# TODO:
#	cleanup??? surely all this hook stuff isn't needed...?
#
#	Copy the 'where_dis.py' into the plugins directory of IDA
#	modify WHERE_DIS_INFO_PATH as needed

WHERE_DIS_INFO_PATH = "D://Temp//" + "where_info" + ".txt"

import sys
from ast import literal_eval
import ida_kernwin
import ida_lines
import idaapi

popup_action_names = []

class hook_helper(idaapi.UI_Hooks):
	def __init__(self):
		idaapi.UI_Hooks.__init__(self)

	def finish_populating_widget_popup(self, form, popup):
		global popup_action_names
		form_type = idaapi.get_widget_type(form)
		if form_type == idaapi.BWN_DISASM:
			for action_name in popup_action_names:
				idaapi.attach_action_to_popup(form, popup, action_name, None)

class action_helper(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def update(self, ctx):
		return idaapi.AST_ENABLE_FOR_WIDGET if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_WIDGET

where_dis = None

def ReloadWhereDisFile():
	global where_dis
	f = open(WHERE_DIS_INFO_PATH, "r")
	if f:
		where_dis = [list(literal_eval(line.strip('#'))) for line in f]
		where_dis.append((0x00000000, 0xFFFFFFFF, "Unknown"))
		f.close()
	else:
		print("WhereDis can't open %s" % WHERE_DIS_INFO_PATH)

class WhereDisPlugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_PROC
	comment = "Check where this symbol was in"
	help = ""
	wanted_name = "WhereDis"
	wanted_hotkey = ""

	def init(self):
		global where_dis
		idaapi.msg("WhereDis init\n")
		AddToPopup('wheredisaction:where_action', 'WhereDis', WhereDisAction(), None, None)
		AddToPopup('wheredisaction:reload_action', 'Reload WhereDis', WhereDisReloadAction(), None, None)
		AddToPopup('wheredisaction:debug_action', 'Debug WhereDis', WhereDisDebugAction(), None, None)
		
		ReloadWhereDisFile()

		self.hooks = hook_helper()
		self.hooks.hook()
		return idaapi.PLUGIN_KEEP

	def run(self):
		idaapi.msg("WhereDis run\n")

	def term(self):
		idaapi.msg("WhereDis term\n")
		if self.hooks:
			self.hooks.unhook()
		idaapi.unregister_action('wheredisaction:where_action')
		idaapi.unregister_action('wheredisaction:reload_action')
		idaapi.unregister_action('wheredisaction:debug_action')

class WhereDisAction(action_helper):
	def activate(self, ctx):
		global where_dis
		
		if len(where_dis) == 0:
			print("where_dis empty!!!!!!")
			return 1
		
		t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
		if idaapi.read_selection(view, t0, t1):
			start, end = t0.place(view).toea(), t1.place(view).toea()
			end += idaapi.get_item_size(end)
		else:
			start = idaapi.get_screen_ea()

			if start == idaapi.BADADDR:
				return 0

			end = start + idaapi.get_item_size(start)

		if start == idaapi.BADADDR:
			return 0

		if start == end:
			return 0

		x = start
		while x < end:
			#print("WhereDis at %x" % x)
			address = x
			for astart, aend, filename in where_dis:
				if address >= astart and address < aend:
					print(format("0x%08X - %s" % (address, filename)))
					break

			isize = idaapi.get_item_size(x)
			if isize != 0:
				x = x + isize
			else:
				x = x + 1

		return 1
		
class WhereDisReloadAction(action_helper):
	def activate(self, ctx):
		global where_dis
		if len(where_dis) != 0:
			del where_dis[:]
		ReloadWhereDisFile()
		#print(where_dis)
		print("WhereDis list reloaded")
		return 1
		
class WhereDisDebugAction(action_helper):
	def activate(self, ctx):
		global where_dis
		if len(where_dis) != 0:
			# check for duplicates
			for i, (s1, en1, f1) in enumerate(where_dis):
				for j, (s2, en2, f2) in enumerate(where_dis):
					if i == j:
						continue
					if s1 > s2 and s1 < en2:
						if s1 != 0 and s2 != 0:
							print("0x%08X overlaps 0x%08X" % (s1, s2))
		else:
			print("where_dis empty!!!!!!")
		
		
		print("WhereDis list debug end")
		return 1

def AddToPopup(action_name, display, handler, shortcut, tooltip, icon=None):
	global popup_action_names

	if tooltip == None:
		tooltip = action_name

	if idaapi.register_action(idaapi.action_desc_t(action_name, display, handler, shortcut, tooltip)):
		popup_action_names.append(action_name)
	else:
		print('WhereDis Error registering action %s' % (action_name))
 
def PLUGIN_ENTRY(*args, **kwargs):
	return WhereDisPlugin()