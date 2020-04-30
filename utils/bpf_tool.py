# coding: utf-8
import logging
import ctypes
import ipaddress 

__author__ = "fripSide"

def load_bpf_prog(filename, params):
	text = ""
	logging.info("Load bpf file: %s", filename)
	with open(filename, "r") as fp:
		text = fp.read()
	for key, val in params.items():
		text = text.replace(f"#define {key} 0", f"#define {key} {val}") 
		logging.info(f"Use param: replace [#define {key} 0] to [#define {key} {val}]")
	return text

def convert_host_addr(host_str):
	"""
	# https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
	ip2int: int(ipaddress.IPv4Address("192.168.0.1"))
	int2ip: str(ipaddress.IPv4Address(3232235521))
	int_max: +2147483647
	"""
	host, port = None, None
	items = host_str.split(":")
	if len(items) == 2:
		port = int(items[1])
	try:
		host = int(ipaddress.IPv4Address(items[0]))
	except Exception as ex:
		logging.error(f"Convert ip address failed ['{host_str}'].")
	return host, port

def bpf_dump_func(bpf, func_name, fi_name):
	fi_name = fi_name.replace(".c", ".txt")
	with open(fi_name, "w") as fp:
		fp.write(bpf.disassemble_func(func_name))

if __name__ == "__main__":
	logging.basicConfig(level=logging.DEBUG)
	ip, port = convert_host_addr("192.168.33.10")
	print(load_bpf_prog("ebpf/tcp_filter.c", {"HOST_IP": ip}))
	print(convert_host_addr("1"))
	print(convert_host_addr("192.168.33.10"))
	print(convert_host_addr("192.168.33.10:8080"))
	print(convert_host_addr("255.255.255.255"))
	# print(str(ipaddress.IPv4Address(-1062723318)))
