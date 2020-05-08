# coding: utf-8
import time
from bcc import BPF
# import pyroute2
import socket
import ipaddress
import logging
import queue
import atexit
import ctypes as ct
from conf import CONFIG

"""
version 1:
1. 根据source ip:port来屏蔽请求。
2. 支持webthings的websocket请求的关键词来屏蔽。
"""


class BlockEndpoint:

	def __init__(self):
		self.ip = 0
		self.port = 0
		self.keyword = ""
		self.allow = False

	def get_key(self):
		return f"{self.ip}:{self.port}"

	def __eq__(self, other):
		if isinstance(other, BlockEndpoint):
			return self.ip == other.ip and self.port == other.port and \
				self.keyword == other.keyword and self.allow == other.allow
		return False

	def __ne__(self, other):
		return not self.__eq__(other)

	def __hash__(self):
		"""Overrides the default implementation"""
		return hash(tuple(self.ip, self.port))

	def get_ctype_data(self):
		"""
		https://docs.python.org/3/library/ctypes.html#fundamental-data-types
		"""
		class Key(ct.Structure):
			_fields_  = [("ip", ct.c_uint32), ("port", ct.c_ushort), ("buf", ct.c_char * 64)]

		class Leaf(ct.Structure):
			_fields_  = [("allow", ct.c_bool)]

		ip = int(ipaddress.IPv4Address(self.ip))
		key = Key(ip, self.port)
		key.buf = self.keyword.encode("utf-8")
		return key, Leaf(self.allow)

class XDPBlackList:

	def __init__(self):
		self.policy_queue = queue.Queue()

	def append_black_list(self, endpoint):
		self.policy_queue.put(endpoint)

	def poll_block_rules(self):
		items = []
		try:
			while True:
				item = self.policy_queue.get(block=True, timeout=0.1)
				items.append(item)
		except queue.Empty:
			pass
		return items

xdp_blacklist = XDPBlackList()

class BpfXDPLoader:

	def __init__(self):
		self.xdp_loaded = False
		self.cur_rules = {}
		self.xdp = None
		self.xdp_flags = 0
		self.in_if = CONFIG.net_interface
		self.xdp_maps = None

	def process_blacklist(self):
		items = xdp_blacklist.poll_block_rules()
		rule_changes = False
		for item in items:
			key = item.get_key()
			if key in self.cur_rules:
				raw_item = self.cur_rules[key]
				if raw_item != item:
					self.cur_rules[key] = item
					rule_changes = True
			else:
				self.cur_rules[key] = item
				rule_changes = True
			
		if rule_changes:
			self.reload()

	def __load_xdp_prog(self):
		if self.xdp_loaded:
			logging.warn("XDP is already loaded.")
			return
		self.xdp_loaded = True
		self.xdp = BPF(src_file=CONFIG.xdp_ebpf_code, cflags=["-w"])
		in_func = self.xdp.load_func(CONFIG.xdp_ebpf_section, BPF.XDP)
		self.xdp.attach_xdp(self.in_if, in_func, self.xdp_flags)
		self.xdp_maps = self.xdp.get_table("blacklist")

	def __update_xdp_maps(self):
		self.xdp_maps.clear()
		for k, item in self.cur_rules.items():
			key, val = item.get_ctype_data()
			self.xdp_maps[key] = val
		# print(type(self.xdp_maps.Key), dir(self.xdp_maps.Key))

	def unload_xdp_prog(self):
		if not self.xdp_loaded:
			return
		logging.info("Unload XDP prog.")
		self.xdp.remove_xdp(self.in_if, self.xdp_flags)
		self.xdp_loaded = False

	def reload(self):
		"""
		version 1: 只是修改maps，不reload
		"""
		if self.xdp_loaded:
			# self.__unload_xdp_prog()
			pass
		if not self.xdp_loaded:
			self.__load_xdp_prog()
		self.__update_xdp_maps()
		
def add_to_blacklist(src_ip, src_port, keyword="", allow=False):
	endpoint = BlockEndpoint()
	endpoint.ip = src_ip
	endpoint.port = src_port
	endpoint.keyword = keyword
	endpoint.allow = allow
	xdp_blacklist.append_black_list(endpoint)

def bpf_test():
	flags = 0
	in_if = "lo"
	b = BPF(src_file="ebpf/xdp_policy.c", cflags=["-w"])
	in_fn = b.load_func("xdp_firewall", BPF.XDP)
	b.attach_xdp(in_if, in_fn, flags)
	print("start to trace pkt:")
	def print_event(cpu, data, size):
		event = b["events"].event(data)
		print("process pkt, version:", event.version, " action:", event.action, "->", str(ipaddress.IPv4Address(event.src_addr)), event.src_port, 
			str(ipaddress.IPv4Address(event.dst_addr)), event.dst_port)

	# loop with callback to print_event
	b["events"].open_perf_buffer(print_event)
	while 1:
			try:
				b.perf_buffer_poll()
			except KeyboardInterrupt:
				print("Unloading...")
				break
	
	b.remove_xdp(in_if, flags)

xdp_loader = BpfXDPLoader()

def main():
	# bpf_test()
	add_to_blacklist("127.0.0.1", 3000)
	while True:
		xdp_loader.process_blacklist()

@atexit.register
def release_xdp():
	xdp_loader.unload_xdp_prog()
