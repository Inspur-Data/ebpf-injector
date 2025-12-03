// SPDX-License-Identifier: GPL-2.0

// 仅包含最基础的bpf帮助函数头文件
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --------------------------------------------------------------------
// --- 手动定义的内核数据结构，消除对 <linux/...> 头文件的依赖 ---
// --------------------------------------------------------------------
#ifndef __u8
#define __u8 unsigned char
#endif
#ifndef __u16
#define __u16 unsigned short
#endif
#ifndef __u32
#define __u32 unsigned int
#endif
#ifndef __be16
#define __be16 __u16
#endif
#ifndef __be32
#define __be32 __u32
#endif

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define ETH_HLEN 14

struct ethhdr {
	unsigned char	h_dest[6];
	unsigned char	h_source[6];
	__be16		h_proto;
};

struct iphdr {
	__u8	ihl:4,
		version:4;
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__u16	check;
	__be32	saddr;
	__be32	daddr;
};

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
	__be16	window;
	__u16	check;
	__u16	urg_ptr;
};
// --------------------------------------------------------------------

// Proxy Protocol v2 头部结构体
struct pp_v2_header {
    __u8 sig[12];
    __u8 ver_cmd;
    __u8 fam;
    __be16 len;
    union {
        struct {
            __be32 src_addr;
            __be32 dst_addr;
            __be16 src_port;
            __be16 dst_port;
        } ipv4;
    } addr;
};

// BPF Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u16);
    __type(value, __u8);
} ports_map SEC(".maps");

SEC("tc")
int tc_proxy_protocol(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (data + sizeof(*eth) > data_end) return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return 0;

    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return 0;
    if (iph->protocol != IPPROTO_TCP) return 0;

    tcph = (void *)iph + sizeof(*iph);
    if ((void *)tcph + sizeof(*tcph) > data_end) return 0;
    
    __u16 target_port = bpf_ntohs(tcph->dest);
    __u8 *val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return 0;

    if (!(tcph->syn && !tcph->ack)) return 0;

    struct pp_v2_header pp_hdr;
    __builtin_memset(&pp_hdr, 0, sizeof(pp_hdr));
    __builtin_memcpy(pp_hdr.sig, "\r\n\r\n\0\r\nQUIT\n", 12);
    pp_hdr.ver_cmd = 0x21;
    pp_hdr.fam     = 0x11;
    pp_hdr.len     = bpf_htons(12);
    pp_hdr.addr.ipv4.src_addr = iph->saddr;
    pp_hdr.addr.ipv4.dst_addr = iph->daddr;
    pp_hdr.addr.ipv4.src_port = tcph->source;
    pp_hdr.addr.ipv4.dst_port = tcph->dest;

    if (bpf_skb_adjust_room(skb, sizeof(pp_hdr), 1, 0))
        return 1;

    if (bpf_skb_store_bytes(skb, ETH_HLEN + iph->ihl * 4 + tcph->doff * 4, &pp_hdr, sizeof(pp_hdr), 0))
        return 1;

    return 0;
}

char _license[] SEC("license") = "GPL";




