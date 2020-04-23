# coding: utf-8
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import sys
import socket
import os
from sys import argv
from policy_monitor import handle_pkt


__author__ = "fripSide"


interface = "lo"

def bpf_hook_socket(inf):
	# initialize BPF - load source code from http-parse-simple.c
	bpf = BPF(src_file = "filter.c", debug = 0)
	# print(dir(bpf))
	# print(bpf.dump_func("my_filter"))

	#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
	#more info about eBPF program types
	#http://man7.org/linux/man-pages/man2/bpf.2.html
	function_http_filter = bpf.load_func("handle_pkt", BPF.SOCKET_FILTER)

	#create raw socket, bind it to interface
	#attach bpf program to socket created
	BPF.attach_raw_socket(function_http_filter, inf)

	#get file descriptor of the socket previously created inside BPF.attach_raw_socket
	socket_fd = function_http_filter.sock

	#create python socket object, from the file descriptor
	sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
	#set it as blocking socket
	sock.setblocking(True)

	return bpf, socket_fd

def print_trace_log(b):
	try:
		(task, pid, cpu, flags, ts, msg) = b.trace_fields()
		print("trace log", msg)
	except ValueError:
		pass

def main():
	bpf, socket_fd = bpf_hook_socket(interface)
	bpf_sessions = bpf.get_table("sessions")
	while True:
		print_trace_log(bpf)
		#retrieve raw packet from socket, 
		# 局域网mtu < 1500, localhost的mtu稍微大一些
  		packet_str = os.read(socket_fd,2048)
		print("packet_str", len(packet_str))
		# 通过session id来获取包
		handle_pkt(packet_str, bpf_sessions)

if __name__ == "__main__":
	main()
