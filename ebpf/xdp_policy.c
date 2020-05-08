#define KBUILD_MODNAME "iot"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
// #include "utils.h"

struct data_t {
	u32 src_addr;
	u32 src_port;
	// port
	u32 dst_addr;
	u32 dst_port;
	u32 action;
	u32 version;
};
BPF_PERF_OUTPUT(events);

/*
xdp只能拦截进来的包，tx流量
*/
// source port
struct EndPoint {
	unsigned short port;
	u32 ipadr;
	char buf[10]; // check websocket buffer keyward
};

struct Rule {
	bool allow;
};

BPF_HASH(blacklist, struct EndPoint, struct Rule, 1024);

#define DPORT 3000

static __always_inline
bool check_blacklist(struct iphdr *iph, struct tcphdr *tcph) {


}

static __always_inline
bool check_content(void *start, void *data_end) {

}

static __always_inline
u32 check_tcp_policy(struct iphdr *iph, struct tcphdr *tcph, void *data_end) {
	if (tcph->dest == htons(DPORT) || tcph->source == htons(DPORT)) {
		
		return XDP_DROP;
	}
	return XDP_PASS;
}

static __always_inline
bool filter_tcp(struct ethhdr *eth, void *data_end, struct iphdr **iph, struct tcphdr **tcph) {
	void *data = (void *) eth;
	u64 eth_off = sizeof(*eth);
	if ((void *)eth + eth_off > data_end) {
		return false;
	}

	// ip v4
	u32 eth_proto = ntohs(eth->h_proto);
	if (eth_proto != ETH_P_IP) {
		return false;
	}

	struct iphdr *ip = data + eth_off;
	eth_off += sizeof(struct iphdr);
	if (data + eth_off > data_end) {
		return false;
	}
	if (ip->protocol != IPPROTO_TCP) {
		return false;
	}

	struct tcphdr *tcp = data + eth_off; 
	eth_off += sizeof(struct tcphdr);
	if (data + eth_off > data_end) {
		return false;
	}

	*iph = ip;
	*tcph = tcp;

	return true;
}

int xdp_firewall(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct tcphdr *tcph; 

	u32 action = XDP_PASS;

	if (!filter_tcp(eth, data_end, &iph, &tcph)) {
		// bpf_debug("Is not tcp packet\n");
		return XDP_PASS; /* Skip */
	}

	action = check_tcp_policy(iph, tcph, data_end);

	// log
	struct data_t ds = {};
	ds.version = 1;
	// ds.src_addr = ntohl(iph->saddr);
	// ds.src_port = ntohs(tcph->source);
	// ds.dst_addr = ntohl(iph->daddr);
	// ds.dst_port = ntohs(tcph->dest);
	// ds.action = action;
	// events.perf_submit(ctx, &ds, sizeof(ds));
	return action;
}
