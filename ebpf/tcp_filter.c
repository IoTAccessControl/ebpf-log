#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include "ebpf/utils.h"

/*
TODO:
1. 看完这几个教程
https://github.com/iovisor/bcc/blob/c2e2a26b8624492018a14d5eebd4a50b869c911f/examples/networking/vlan_filter/data-plane-tracing.c


2. 总结要点

*/

#define IP_TCP 	6
#define ETH_HLEN 14

struct Key {
	u32 src_ip;               //source ip
	u32 dst_ip;               //destination ip
	unsigned short src_port;  //source port
	unsigned short dst_port;  //destination port
};

struct Leaf {
	int timestamp;            //timestamp in ns
};

//BPF_TABLE(map_type, key_type, leaf_type, table_name, num_entry)
//map <Key, Leaf>
//tracing sessions having same Key(dst_ip, src_ip, dst_port,src_port)
BPF_HASH(sessions, struct Key, struct Leaf, 1024);

static __always_inline int is_http_pkt(struct __sk_buff *skb, u32 payload_offset) {
	u8* header[6] = {"HTTP", "PUT", "GET", "POST", "DELETE", "HEAD"};

	u8 buf[7];
	for (int i = 0; i < 7; i++) {
		buf[i] = load_byte(skb , payload_offset + i);
	}
	// for 循环读取报错，reference a global or static variable, or data in read-only section
	// for (int i = 0; i < 6; i++) {
	// 	if (mstrcmp(header[i], buf, 10) == 1) {
	// 		return 1;
	// 	}
	// }
	if (mstrcmp(header[0], buf, 10) == 1) {
		return 1;
	}
	if (mstrcmp(header[1], buf, 10) == 1) {
		return 1;
	}
	if (mstrcmp(header[2], buf, 10) == 1) {
		return 1;
	}
	if (mstrcmp(header[3], buf, 10) == 1) {
		return 1;
	}
	if (mstrcmp(header[4], buf, 10) == 1) {
		return 1;
	}
	if (mstrcmp(header[5], buf, 10) == 1) {
		return 1;
	}
	return 0;
}

// 注意变量最好初始化在最前面，防止不小心goto跳过了初始化
int handle_pkt(struct __sk_buff *skb) {
	u8 *cursor = 0;
	struct Key 	key;
	struct Leaf zero = {0};
	u32 tcp_header_length = 0;
	u32 ip_header_length = 0;
	u32 ip_total_length = 0;
	u32 payload_offset = 0;
	u32 payload_length = 0;

	ethernet: {
		struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
		switch (ethernet->type) {
			case 0x0800: goto ip;
			default: goto DROP;
		}
	}

	ip: {
		struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
		key.src_ip = ip->src;
		key.dst_ip = ip->dst;
		ip_header_length = ip->hlen << 2;
		ip_total_length = ip->tlen;

		if (ip_header_length < sizeof(*ip)) {
			goto DROP;
		}
	
		//shift cursor forward for dynamic ip header size
		void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

		switch (ip->nextp) {
			case IP_TCP: goto tcp;
			default: goto DROP;
		}
	}

	tcp: {
		struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

		key.src_port = tcp->src_port;
		key.dst_port = tcp->dst_port;

		//calculate tcp header length
		//value to multiply *4
		//e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
		tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

		//calculate payload offset and length
		payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
		payload_length = ip_total_length - ip_header_length - tcp_header_length;

		//http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
		//minimum length of http request is always geater than 7 bytes
		//avoid invalid access memory
		//include empty payload
		if(payload_length < 7) {
			goto DROP;
		}
		
		if (is_http_pkt(skb, payload_offset)) {
			goto HTTP_MATCH;
		} 

		// no HTTP match
		// check if packet belong to an HTTP session
		struct Leaf * lookup_leaf = sessions.lookup(&key);
		if(lookup_leaf) {
			//send packet to userspace
			goto KEEP;
		}
		goto DROP;
	}

HTTP_MATCH:
	bpf_trace_printk("tcp: %d %d\n", 14, payload_offset);
	sessions.lookup_or_try_init(&key, &zero);

KEEP:
	return -1;

DROP:
	return 0;
}
