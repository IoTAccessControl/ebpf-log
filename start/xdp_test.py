# coding: utf-8
import time
from bcc import BPF
from bcc.utils import printb
# import pyroute2
import socket
import ipaddress


__author__ = "fripSide"

# https://github.com/YutaroHayakawa/vale-bpf

"""
1. xdp drop tcp packet
https://gist.github.com/yunazuno/6227bd7e7b8382d2d11b44baed1a94f9

2. TODO:用event输出
"""


def task1_xdp_drop():
	# 
	bpf_text = """
	#define KBUILD_MODNAME "foo"
	#include <linux/bpf.h>
	#include <linux/in.h>
	#include <linux/if_ether.h>
	#include <linux/ip.h>
	#include <linux/udp.h>
	#include <linux/tcp.h>

	#define SEC(NAME) __attribute__((section(NAME), used))

	#define htons(x) ((__be16)___constant_swab16((x)))

	#define DPORT 3000

	BPF_HASH(counter, uint32_t, long);

	// drop tcp tx/rx port 3000
	// SEC("tcp_pass2")
	int tcp_pass(struct xdp_md *ctx) {
		int eth_off = 0;
		u32 index = 0;
		long *value;
    	long zero = 0;

		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		struct ethhdr *eth = data;
		eth_off = sizeof(*eth);

		struct iphdr *ip = data + eth_off;
		eth_off += sizeof(struct iphdr);
		if (data + eth_off > data_end) {
			return XDP_PASS;
		}

		struct tcphdr *tcph = data + eth_off; 
		eth_off += sizeof(struct tcphdr);
		if (data + eth_off > data_end) {
			return XDP_PASS;
		}
		u32 src_ip = 3232243978;
		//bpf_trace_printk("dest:%u %d\\n", ntohl(ip->daddr), ntohs(tcph->dest));
		if (ip->protocol == IPPROTO_TCP && tcph->source == htons(DPORT)) {
			bpf_trace_printk("source: %u %d\\n", ntohl(ip->saddr), ntohs(tcph->source));
			bpf_trace_printk("drop packet: ip:%u %d\\n", ntohl(ip->daddr), ntohs(tcph->dest));
			index = (uint32_t) tcph->source;
            value = counter.lookup_or_init(&index, &zero);
            (*value) += 1;
			return XDP_DROP;
		}
		
		bpf_trace_printk("pass packet: ip:%u %d\\n", ntohl(ip->daddr), ntohs(tcph->dest));
		return XDP_PASS;
	}
	"""
	flags = 0
	in_if = "lo"
	b = BPF(text=bpf_text, cflags=["-w"])
	in_fn = b.load_func("tcp_pass", BPF.XDP)
	b.attach_xdp(in_if, in_fn, flags)
	print( str(ipaddress.IPv4Address(3232243978)))
	print("Running nologic program, hit CTRL+C to stop")
	counter = b.get_table("counter")
	while 1:
		try:
			for k, v in counter.items():  # type(k) = c_uint, type(v) = c_long
				print("{}: {}".format(k.value, v.value))
			(task, pid, cpu, f, ts, msg) = b.trace_fields()
			print(task, msg)
			time.sleep(1)
		except KeyboardInterrupt:
			print("Unloading...")
			break;
	b.remove_xdp(in_if, flags)
	print("exit")

def task2_xdp_start():
	device = "lo"
	print(socket.if_nametoindex("eth1"))
	mode = BPF.XDP
	print(socket.if_nameindex())
	ret = "XDP_TX"
	ctxtype = "xdp_md"
	flags = 0
	b = BPF(src_file="xdp.c", cflags=["-w", "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype])
	fn = b.load_func("xdp_prog1", mode)
	b.attach_xdp(device, fn, flags)
	dropcnt = b.get_table("dropcnt")
	prev = [0] * 256
	print("Printing drops per IP protocol-number, hit CTRL+C to stop")
	while 1:
		try:
			for k in dropcnt.keys():
				val = dropcnt.sum(k).value
				i = k.value
				if val:
					delta = val - prev[i]
					prev[i] = val
					print("{}: {} pkt/s".format(i, delta))
			time.sleep(1)
		except KeyboardInterrupt:
			print("Removing filter from device")
			break;

	b.remove_xdp(device, flags)

def task3_xdp_exp():
	bpf_text = """
	#define KBUILD_MODNAME "xdp"
	#include <linux/bpf.h>
	#include <linux/in.h>
	#include <linux/if_ether.h>
	#include <linux/ip.h>
	#include <linux/udp.h>
	#include <linux/tcp.h>

	#define DPORT 8888

	// define output data structure in C
	struct data_t {
		u32 src_addr;
		u32 src_port;
		// port
		u32 dst_addr;
		u32 dst_port;
	};
	BPF_PERF_OUTPUT(events);

	int track_dest(struct xdp_md *ctx) {
		int eth_off = 0;
		struct data_t ds = {};
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		struct ethhdr *eth = data;
		eth_off = sizeof(*eth);

		struct iphdr *ip = data + eth_off;
		eth_off += sizeof(struct iphdr);
		if (data + eth_off > data_end) {
			return XDP_PASS;
		}

		struct tcphdr *tcph = data + eth_off; 
		eth_off += sizeof(struct tcphdr);
		if (data + eth_off > data_end) {
			return XDP_PASS;
		}

		

		if (ip->protocol == IPPROTO_TCP && tcph->dest == htons(DPORT) || tcph->source == htons(DPORT)) {
			//bpf_trace_printk("drop packet: %d -> %u %d\\n", ntohs(tcph->source), ntohl(ip->daddr), ntohs(tcph->dest));
			ds.src_addr = ntohl(ip->saddr);
			ds.src_port = ntohs(tcph->source);
			ds.dst_addr = ntohl(ip->daddr);
			ds.dst_port = ntohs(tcph->dest);
			events.perf_submit(ctx, &ds, sizeof(ds));
			return XDP_DROP;
		}
	
		// dest
		//bpf_trace_printk("pass packet: ip:%u %d\\n", ntohl(ip->daddr), ntohs(tcph->dest));
		return XDP_PASS;
	}
	"""
	flags = 0
	in_if = "eth1"
	b = BPF(text=bpf_text, cflags=["-w"])
	in_fn = b.load_func("track_dest", BPF.XDP)
	b.attach_xdp(in_if, in_fn, flags)
	print("start to trace pkt:")
	def print_event(cpu, data, size):
		event = b["events"].event(data)
		print("drop pkt: ", str(ipaddress.IPv4Address(event.src_addr)), event.src_port, 
			str(ipaddress.IPv4Address(event.dst_addr)), event.dst_port)

	# loop with callback to print_event
	b["events"].open_perf_buffer(print_event)
	while 1:
			try:
				b.perf_buffer_poll()
			except KeyboardInterrupt:
				print("Unloading...")
				break;
	
	b.remove_xdp(in_if, flags)

def main():
	# task1_xdp_drop()
	# task1_xdp_start()
	task3_xdp_exp()

if __name__ == "__main__":
	main()
