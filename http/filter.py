# coding: utf-8
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from conf import CONFIG
import sys
import struct
import socket
import os
import logging
import ipaddress 
import binascii
from collections import namedtuple
from http.policy_monitor import policy_manager

__author__ = "fripSide"

"""
Caputre ip packet and parser http data.
Manage http sessions.

TODO:
1. 

"""

TcpEndpoint = namedtuple("TcpEndpoint", ["ip_src", "ip_dst", "port_src", "port_dst"])

def bpf_hook_socket():
	# initialize BPF - load source code from http-parse-simple.c
	bpf = BPF(src_file=CONFIG.http_filter_ebpf, debug = 0)
	# print(dir(bpf))
	# print(bpf.dump_func("my_filter"))

	#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
	#more info about eBPF program types
	#http://man7.org/linux/man-pages/man2/bpf.2.html
	function_http_filter = bpf.load_func(CONFIG.http_ebpf_section, BPF.SOCKET_FILTER)

	#create raw socket, bind it to interface
	#attach bpf program to socket created
	BPF.attach_raw_socket(function_http_filter, CONFIG.net_interface)

	#get file descriptor of the socket previously created inside BPF.attach_raw_socket
	socket_fd = function_http_filter.sock

	#create python socket object, from the file descriptor
	sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
	#set it as blocking socket
	sock.setblocking(True)

	return bpf, socket_fd

def print_trace_log(b):
	if not CONFIG.debug:
		return
	try:
		(task, pid, cpu, flags, ts, msg) = b.trace_fields(nonblocking=True)
		if msg:
			print("trace log:", msg)
	except ValueError:
		pass

class TcpSession:
	"""
	1. 维护ebpf的session数组，将过期的session删掉
	2. 从多个tcp包中获取一个完整的http请求
	3. 排除无效的包
	"""
	CLEANUP_N_PACKETS = 50
	MAX_AGE_SECONDS = 30

	def __init__(self, bpf_sessions):
		self.bpf_sessions = bpf_sessions
		self.first_pkt = {}
		self.pkt_count = 0

	def get_key(self, ip_src, port_src, ip_dst, port_dst):
		ip_src = int(ipaddress.IPv4Address(ip_src))
		ip_dst = int(ipaddress.IPv4Address(ip_dst))
		key = self.bpf_sessions.Key(ip_src, ip_dst, port_src, port_dst)
		# print("raw", ip_src, ip_dst, port_src, port_dst)
		# print("key", self.__dump_key(key))
		return key

	def is_valid_http_data(self, key, tcp_payload):
		self.pkt_count += 1
		pkt_key = binascii.hexlify(key)
		if self.__is_http_begin(tcp_payload):
			# print("is header", tcp_payload[:5])
			self.first_pkt[pkt_key] = True
			if self.__is_http_end(tcp_payload):
				del self.first_pkt[pkt_key]
				self.__delete_bpf_session(key)
			return tcp_payload

		if key in self.bpf_sessions:
			if pkt_key in self.first_pkt:
				if self.__is_http_end(tcp_payload):
					del self.first_pkt[pkt_key]
					self.__delete_bpf_session(key)
			else:
				# first part of the HTTP GET/POST url is
				# NOT present in local dictionary
				# bpf_sessions contains invalid entry -> delete it
				self.__delete_bpf_session(key)
		return None

	def __dump_key(self, ky):
		return ky.dst_ip, ky.src_ip, ky.src_port, ky.dst_port

	def __delete_bpf_session(self, key):
		# print("__delete_bpf_session")
		# for ky, leaf in self.bpf_sessions.items():
		# 	print(self.__dump_key(ky), leaf.timestamp)
		# print(self.__dump_key(key))
		if key not in self.bpf_sessions:
			return
		try:
			del self.bpf_sessions[key]
			# print("__delete_bpf_session suc")
		except:
			logging.warning("error del bpf_session")

	def __is_http_begin(self, payload_string):
		if ((payload_string[:3] == b'GET') or (payload_string[:4] == b'POST')
			or (payload_string[:4] == b'HTTP') or (payload_string[:3] == b'PUT')
			or (payload_string[:6] == b'DELETE') or (payload_string[:4] == b'HEAD')):
			return True
		return False

	def __is_http_end(self, data):
		crlf = b'\r\n'
		return crlf in data

	def try_to_clean(self):
		if (self.pkt_count % self.CLEANUP_N_PACKETS) != 0:
			return
		current_time = int(time.time())
		# looking for leaf having:
		# timestap  == 0        --> update with current timestamp
		# AGE > MAX_AGE_SECONDS --> delete item
		for key, leaf in self.bpf_sessions.items():
			try:
				current_leaf = self.bpf_sessions[key]
				# set timestamp if timestamp == 0
				if (current_leaf.timestamp == 0):
					self.bpf_sessions[key] = self.bpf_sessions.Leaf(current_time)
				else:
					# delete older entries
					if (current_time - current_leaf.timestamp > MAX_AGE_SECONDS):
						del self.bpf_sessions[key]
			except:
				logging.warning("cleanup exception.")

def dispatch_pkt(data, tcp_session):
	# 从IP包开始解析数据
	packet_bytearray = bytearray(data)

	#ethernet header length
	ETH_HLEN = 14
	#IP HEADER
	#https://tools.ietf.org/html/rfc791
	# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |Version|  IHL  |Type of Service|          Total Length         |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#
	#IHL : Internet Header Length is the length of the internet header
	#value to multiply * 4 byte
	#e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
	#
	#Total length: This 16-bit field defines the entire packet size,
	#including header and data, in bytes.

	#calculate packet total length
	total_length = packet_bytearray[ETH_HLEN + 2]               #load MSB
	total_length = total_length << 8                            #shift MSB
	total_length = total_length + packet_bytearray[ETH_HLEN+3]  #add LSB
	
	#calculate ip header length
	ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
	ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
	ip_header_length = ip_header_length << 2                    #shift to obtain length

	ip_src_bys = packet_bytearray[ETH_HLEN + 12: ETH_HLEN + 16] # ip source offset 12..15
	ip_dst_bys = packet_bytearray[ETH_HLEN + 16: ETH_HLEN + 20] # ip dest   offset 16..19
	ip_src = socket.inet_ntoa(ip_src_bys)
	ip_dst = socket.inet_ntoa(ip_dst_bys)

	#TCP HEADER
	#https://www.rfc-editor.org/rfc/rfc793.txt
	#  12              13              14              15
	#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  Data |           |U|A|P|R|S|F|                               |
	# | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
	# |       |           |G|K|H|T|N|N|                               |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#
	#Data Offset: This indicates where the data begins.
	#The TCP header is an integral number of 32 bits long.
	#value to multiply * 4 byte
	#e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

	#calculate tcp header length
	tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  #load Byte
	tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7
	tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2

	# retrieve port source/dest
	port_src_bys = packet_bytearray[ETH_HLEN + ip_header_length:ETH_HLEN + ip_header_length + 2]
	port_dst_bys = packet_bytearray[ETH_HLEN + ip_header_length + 2:ETH_HLEN + ip_header_length + 4]
	port_src = int.from_bytes(port_src_bys, CONFIG.byte_order)
	port_dst = int.from_bytes(port_dst_bys, CONFIG.byte_order)

	#calculate payload offset
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length
	tcp_payload = packet_bytearray[payload_offset:]

	tcp_endpoint = TcpEndpoint(ip_src, ip_dst, port_src,  port_dst)
	session_key = tcp_session.get_key(ip_src, port_src, ip_dst, port_dst)

	# get http data
	ret = tcp_session.is_valid_http_data(session_key, tcp_payload)
	if ret:
		policy_manager.append_http_data(tcp_endpoint, tcp_payload)
	tcp_session.try_to_clean()

def main():
	bpf, socket_fd = bpf_hook_socket()
	bpf_sessions = bpf.get_table("sessions")
	tcp_session = TcpSession(bpf_sessions)
	while True:
		print_trace_log(bpf)
		# set to mtu (1500) 
		packet_str = os.read(socket_fd, 4096)
		# 通过session id来获取tcp流中完整的http请求
		dispatch_pkt(packet_str, tcp_session)
