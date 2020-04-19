# coding: utf-8
# created at 2020/4/18
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import sys
import socket
import os


__author__ = "fripSide"

"""
TODO:
1. 基本教程: 无脑写完16个教程
2. nodejs，trace
3. HTTP filter
"""

SEC = 1000000000
MS = 1000000

#args
def usage():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i if_name               select interface if_name. Default is eth0")
    print("")
    print("examples:")
    print("    http-parse              # bind socket to eth0")
    print("    http-parse -i wlan0     # bind socket to wlan0")
    exit()

class Config:

	#arguments
	interface="eth0"
	bpf_code = "first.c"

CONFIG = Config()

def task2_sys_sync():
	# 另一个窗口输入 sync命令即可测试
	p = """
	int kprobe__sys_sync(void *ctx) {
		bpf_trace_printk("Hello, sys_sync!\\n"); 
		return 0;
	}
	"""
	b = BPF(text=p)
	b.trace_print()

def task3_fileds():
	# define BPF program
	prog = """
	int hello(void *ctx) {
		bpf_trace_printk("Hello, Clone!\\n");
		return 0;
	}
	"""

	# load BPF program
	b = BPF(text=prog)
	b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

	# header
	print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

	# format output
	while 1:
		try:
			(task, pid, cpu, flags, ts, msg) = b.trace_fields()
		except ValueError:
			continue
		print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

def task4_sync_timing():
	p = """
		#include <uapi/linux/ptrace.h>

		BPF_HASH(last);

		int do_trace(struct pt_regs *ctx) {
			u64 ts, *tsp, delta, key = 0;

			// attempt to read stored timestamp
    		tsp = last.lookup(&key);
			if (tsp != 0) {
				delta = bpf_ktime_get_ns() - *tsp;
				if (delta < 1000000000) {
					// output if time is less than 1 second
            		bpf_trace_printk("%d\\n", delta / 1000000);
				}
				last.delete(&key);
			}

			// update stored timestamp
			ts = bpf_ktime_get_ns();
			last.update(&key, &ts);
			return 0;
		}
	"""
	b = BPF(text=p)
	b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
	print("Tracing for quick sync's... Ctrl-C to end")
	# format output
	start = 0
	while 1:
		ret = b.trace_fields()
		print(ret)
		(task, pid, cpu, flags, ts, ms) = ret
		if start == 0:
			start = ts
		ts = ts - start
		print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))

def task5_sync_count():
	p = """
		#include <uapi/linux/ptrace.h>

		BPF_HASH(last);

		int do_trace(struct pt_regs *ctx) {
			u64 ts, *tsp, key = 0;

			// attempt to read stored timestamp
    		tsp = last.lookup(&key);
			if (tsp == NULL) {
				ts = 0;
			} else {
				ts = *tsp;
			}
			ts++;
			bpf_trace_printk("%d\\n", ts);
			last.update(&key, &ts);
			return 0;
		}
	"""
	b = BPF(text=p)
	b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
	print("Tracing for quick sync's... Ctrl-C to end")
	# format output
	start = 0
	while 1:
		ret = b.trace_fields()
		print(ret)
		(task, pid, cpu, flags, ts, ms) = ret
		if start == 0:
			start = ts
		ts = ts - start
		print("At time %.2f s: call sync, current count: %s times" % (ts, ms))

def task6_disk_snoop():
	# disk请求时间
	REQ_WRITE = 1
	p = """
	#include <uapi/linux/ptrace.h>
	#include <linux/blkdev.h>

	BPF_HASH(start, struct request *);

	void trace_start(struct pt_regs *ctx, struct request *req) {
		// stash start timestamp by request ptr
		u64 ts = bpf_ktime_get_ns();
		start.update(&req, &ts);
	}

	void trace_completion(struct pt_regs *ctx, struct request *req) {
		u64 *tsp, delta;
		tsp = start.lookup(&req);
		if (tsp != 0) {
			delta = bpf_ktime_get_ns() - *tsp;
			bpf_trace_printk("%d %x %d\\n", req->__data_len,
				req->cmd_flags, delta / 1000);
			start.delete(&req);
		}
	}
	"""
	b = BPF(text=p)
	if BPF.get_kprobe_functions(b'blk_start_request'):
		b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
	b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
	b.attach_kprobe(event="blk_account_io_completion", fn_name="trace_completion")

	print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

	while True:
		try:
			(task, pid, cpu, flags, ts, msg) = b.trace_fields()
			(bytes_s, bflags_s, us_s) = msg.split()

			if int(bflags_s, 16) & REQ_WRITE:
				type_s = b"W"
			elif bytes_s == "0":
				type_s = b"M"
			else:
				type_s = b"R"
			ms = float(int(us_s, 10)) / 1000
			printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))
		except KeyboardInterrupt:
			exit()

start = 0
def task7_hello_pref_out():
	p = """
	#include <linux/sched.h>

	struct data_t {
		u32 pid;
		u64 ts;
		char comm[TASK_COMM_LEN];
	};
	BPF_PERF_OUTPUT(ev);

	int hello(struct pt_regs *ctx) {
    	struct data_t data = {};
		data.pid = bpf_get_current_pid_tgid();
		data.ts = bpf_ktime_get_ns();
		bpf_get_current_comm(&data.comm, sizeof(data.comm));

		ev.perf_submit(ctx, &data, sizeof(data));
		return 0;
	}
	"""
	b = BPF(text=p)
	b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

	# header
	print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

	def print_event(cpu, data, size):
		global start
		event = b["ev"].event(data)
		if start == 0:
			start = event.ts
		time_s = (float(event.ts - start)) / SEC
		print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
        "Hello, perf_output!"))

	# loop with callback to print_event
	b["ev"].open_perf_buffer(print_event)
	while 1:
		b.perf_buffer_poll()

def task8_output_sync():
	p = """
	#include <uapi/linux/ptrace.h>

	struct data_t {
		u32 pid;
		u64 ts;
		u64 ms;
		u32 flags;
	};
	BPF_PERF_OUTPUT(ev);
	BPF_HASH(last);

	int do_trace(struct pt_regs *ctx) {
		u64 ts, *tsp, delta, key = 0;

		// attempt to read stored timestamp
		tsp = last.lookup(&key);
		if (tsp != 0) {
			delta = bpf_ktime_get_ns() - *tsp;
			if (delta < 1000000000) {
				// output if time is less than 1 second
				//bpf_trace_printk("%d\\n", delta / 1000000);
				struct data_t data = {};
				data.pid = bpf_get_current_pid_tgid();
				data.ts = bpf_ktime_get_ns();
				data.ms = delta / 1000000;
				ev.perf_submit(ctx, &data, sizeof(data));
			}
			last.delete(&key);
		}

		// update stored timestamp
		ts = bpf_ktime_get_ns();
		last.update(&key, &ts);
		
		return 0;
	}
	"""
	b = BPF(text=p)
	b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
	print("Tracing for quick sync's... Ctrl-C to end")

	# format output
	def print_event(cpu, data, size):
		global start
		event = b["ev"].event(data)
		if start == 0:
			start = event.ts
		ms = event.ms
		ts = (event.ts - start) / MS
		print("At time %.2f ms: multiple syncs detected, last %s ms ago" % (ts, ms))
	b["ev"].open_perf_buffer(print_event)
	while 1:
		b.perf_buffer_poll()

from time import sleep
def task9_bitehist():
	p = """
	#include <uapi/linux/ptrace.h>
	#include <linux/blkdev.h>

	BPF_HISTOGRAM(dist);

	int kprobe__blk_account_io_completion(struct pt_regs *ctx, struct request *req)
	{
		dist.increment(bpf_log2l(req->__data_len / 1024));
		return 0;
	}
	"""
	# dist.increment，直接对直方图的key + 1
	# bpf_log2l 取log2对数
	# 注意ctrl-c之后才print

	b = BPF(text=p)
	# header
	print("Tracing... Hit Ctrl-C to end.")
	# trace until Ctrl-C
	try:
		sleep(99999999)
	except KeyboardInterrupt:
		print()

	# output
	b["dist"].print_log2_hist("kbytes")

def task10_disklatency():
	p = """
	#include <uapi/linux/ptrace.h>
	#include <linux/blkdev.h>

	BPF_HISTOGRAM(dist);
	BPF_HASH(start, struct request *);

	// int kprobe__blk_start_request(struct pt_regs *ctx, struct request *req) {
	void trace_start(struct pt_regs *ctx, struct request *req) {
		// stash start timestamp by request ptr
		u64 ts = bpf_ktime_get_ns();

		start.update(&req, &ts);
		//return 0;
	}

	// int kprobe__blk_account_io_completion(struct pt_regs *ctx, struct request *req) {
	void trace_completion(struct pt_regs *ctx, struct request *req) {
		u64 *tsp, delta;

		tsp = start.lookup(&req);
		if (tsp != 0) {
			delta = bpf_ktime_get_ns() - *tsp;
			dist.increment(bpf_log2l(delta / 1000));
			start.delete(&req);
		}
		//return 0;
	}
	"""
	b = BPF(text=p)
	b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
	b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
	b.attach_kprobe(event="blk_account_io_completion", fn_name="trace_completion")
	# header
	print("Tracing... Hit Ctrl-C to end.")

	# trace until Ctrl-C
	try:
		sleep(10)
	except KeyboardInterrupt:
		print()
	# output
	b["dist"].print_log2_hist("ms")

def task11_vfsreadlat():
	b = BPF(src_file = "vfsreadlat.c")
	b.attach_kprobe(event="vfs_read", fn_name="do_entry")
	b.attach_kretprobe(event="vfs_read", fn_name="do_return")

	# header
	print("Tracing... Hit Ctrl-C to end.")

	interval = 5
	count = 3
	# output
	loop = 0
	do_exit = 0
	while (1):
		if count > 0:
			loop += 1
			if loop > count:
				exit()
		try:
			sleep(interval)
		except KeyboardInterrupt:
			pass; do_exit = 1

		print()
		b["dist"].print_log2_hist("usecs")
		b["dist"].clear()

def task12_urandomread():
	p = """
	TRACEPOINT_PROBE(random, urandom_read) {
		// args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
		bpf_trace_printk("%d\\n", args->got_bits);
		return 0;
	}
	"""
	b = BPF(text=p)
	# header
	print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "GOTBITS"))

	# format output
	while 1:
		try:
			(task, pid, cpu, flags, ts, msg) = b.trace_fields()
		except ValueError:
			continue
		except KeyboardInterrupt:
			exit()
		printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

def task13_fix_disksnoop():
	# https://github.com/cloudflare/ebpf_exporter/blob/master/examples/bio-tracepoints.yaml
	p = """
	#include <uapi/linux/ptrace.h>
	#include <linux/blkdev.h>

	struct key_t {
		dev_t dev;
		sector_t sector;
	};

	struct val_t {
		u64 start;
		u64 bytes;
	};

	BPF_HASH(start, struct key_t, struct val_t);
	//BPF_HASH(start, struct request *);

	TRACEPOINT_PROBE(block, block_rq_issue) {
	// void trace_start(struct pt_regs *ctx, struct request *req) {
		// stash start timestamp by request ptr
		if (args->dev == 0) {
			return 0;
		}
		struct key_t key = {};
		key.dev = args->dev;
		key.sector = args->sector;
		if (key.sector == -1) {
			key.sector = 0;
		}

		
		struct val_t val = {};
		val.start = bpf_ktime_get_ns();
		val.bytes = args->bytes;
		start.update(&key, &val);
		return 0;
	}

	TRACEPOINT_PROBE(block, block_rq_complete) {
	// void trace_completion(struct pt_regs *ctx, struct request *req) {
		u64 delta;
		struct key_t key = {};
		key.dev = args->dev;
		key.sector = args->sector;
		if (key.sector == -1) {
			key.sector = 0;
		}
		struct val_t *valp = start.lookup(&key);
		if (valp == 0) {
			return 0; // missed issue
		}
		u64 size_kib = valp->bytes / 1024;
		delta = (bpf_ktime_get_ns() - valp->start) / 1000;
		bpf_trace_printk("%d %x %d\\n", size_kib,
			2, delta);
		start.delete(&key);
		return 0;
	}
	"""
	b = BPF(text=p)

	# header
	print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))
	REQ_WRITE = 1
	# format output
	while 1:
		try:
			(task, pid, cpu, flags, ts, msg) = b.trace_fields()
			(bytes_s, bflags_s, us_s) = msg.split()

			if int(bflags_s, 16) & REQ_WRITE:
				type_s = b"W"
			elif bytes_s == "0":	# see blk_fill_rwbs() for logic
				type_s = b"M"
			else:
				type_s = b"R"
			ms = float(int(us_s, 10)) / 1000

			printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))
		except KeyboardInterrupt:
			exit()

def task14_strlen_count():
	# TODO: 搞清楚为什么输出不是str，而是libc版本，LIBC_2.2.5
	p = """
	#include <uapi/linux/ptrace.h>

	struct key_t {
		char c[80];
	};
	BPF_HASH(counts, struct key_t);

	int count(struct pt_regs *ctx) {
		if (!PT_REGS_PARM1(ctx))
        	return 0;
		struct key_t key = {};
    	u64 zero = 0, *val;
		bpf_probe_read(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
		bpf_trace_printk("%s\\n", key.c);
		// could also use `counts.increment(key)`
		val = counts.lookup_or_try_init(&key, &zero);
		if (val) {
			(*val)++;
		}
		return 0;
	}
	"""
	b = BPF(text=p)
	b.attach_uprobe(name="c", sym="strlen", fn_name="count")

	# header
	print("Tracing strlen()... Hit Ctrl-C to end.")

	# sleep until Ctrl-C
	try:
		sleep(10)
	except KeyboardInterrupt:
		pass

	# print output
	print("%10s %s" % ("COUNT", "STRING"))
	counts = b.get_table("counts")
	print(counts)
	for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
		print("%10d \"%s\"" % (v.value, k.c.encode('string-escape')))
		print(type(k.c), k.c)
	print(b.trace_fields())

def task14_strlen_copy():
	# https://blog.csdn.net/tiantao2012/article/details/79027852
	#定义并load一个BPF函数
	b = BPF(text="""
	#include <uapi/linux/ptrace.h>
	// 定义一个结构体，包括调用strlen程序的name
	struct key_t {
		char c[80];
	};
	// 定义一个hash 表，并指明类型
	BPF_HASH(counts, struct key_t);
	int count(struct pt_regs *ctx) {
		//这里的PT_REGS_PARM1 会fetch 第一个参数
		if (!PT_REGS_PARM1(ctx))
			return 0;
		struct key_t key = {};
		u64 zero = 0, *val;
		// 这样函数就会通过PT_REGS_PARM1 fetch的值保存到key中，这个值就是使用strlen的程序
		bpf_probe_read(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
		 //hash 表查找是否有这个key，如果没有的话就初始化，有的话就子加1
		val = counts.lookup_or_init(&key, &zero);
		(*val)++;
		return 0;
	};
	""")
	#这里是通关过attach_uprobe 来attach到c 库中，当有人调用c库中的streln函数时
	#就会调用count函数
	#这里的c指的是libc。可以省掉前面的lib三个字
	b.attach_uprobe(name="c", sym="strlen", fn_name="count")
	
	# header
	print("Tracing strlen()... Hit Ctrl-C to end.")
	#睡眠直到用户按下CTRL+C
	# sleep until Ctrl-C
	try:
		sleep(10)
	except KeyboardInterrupt:
		pass
	
	# print output
	print("%10s %s" % ("COUNT", "STRING"))
	#得到c函数中定义的hash表，然后排序打印出来
	counts = b.get_table("counts")
	for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
		print("%10d \"%s\"" % (v.value, k.c.encode('string-escape')))

def task15_nodejs_server():
	# 安装nodejs（不可行）：
	# 1. curl -sL https://deb.nodesource.com/setup_13.x | sudo -E bash -
	# 2. 切换成贵清的源，https://mirror.tuna.tsinghua.edu.cn/help/nodesource/
	# 3. sudo apt-get install -y nodejs
	
	# 安装http-server模块：https://www.npmjs.com/package/http-server
	# 启动nodejs server: 
	#
	# 测试：

	"""
	需要自己build node (./configure --with-dtrace)
	http://www.brendangregg.com/blog/2016-10-12/linux-bcc-nodejs-usdt.html
	"""
	from bcc import BPF, USDT
	p = """
	#include <uapi/linux/ptrace.h>
	int do_trace(struct pt_regs *ctx) {
		uint64_t addr;
		char path[128]={0};
		bpf_usdt_readarg(6, ctx, &addr);
		bpf_probe_read(&path, sizeof(path), (void *)addr);
		bpf_trace_printk("path:%s\\n", path);
		return 0;
	};
	"""
	pid = 6816 
	u = USDT(pid=int(pid))
	u.enable_probe(probe="http__server__request", fn_name="do_trace")
	print(u.get_text())

	# initialize BPF
	b = BPF(text=p, usdt_contexts=[u])
	b = USDT(text=p)

def task16_task_switch():
	b = BPF(src_file="task_switch.c")
	b.attach_kprobe(event="finish_task_switch", fn_name="count_sched")

	# generate many schedule events
	for i in range(0, 100): sleep(0.01)

	for k, v in b["stats"].items():
		print("task_switch[%5d->%5d]=%u" % (k.prev_pid, k.curr_pid, v.value))


def main():
	# task2_sys_sync()
	# task3_fileds()
	# task4_sync_timing()
	# task5_sync_count()
	# task6_disk_snoop()
	# task7_hello_pref_out()
	# task8_output_sync()
	# task9_bitehist()
	# task10_disklatency()
	# task11_vfsreadlat()
	# task12_urandomread()
	# task13_fix_disksnoop()
	# task14_strlen_count()
	# task14_strlen_copy() # 仍然有问题
	task15_nodejs_server()
	# task16_task_switch()


if __name__ == "__main__":
	main()
