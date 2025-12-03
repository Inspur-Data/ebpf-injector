// SPDX-License-Identifier: GPL-2.0

// 包含最基础的系统头文件
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

// 包含libbpf提供的帮助函数
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

// BPF Map，用于存储要处理的端口
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
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    __u16 target_port;
    __u8 *val;

    // --- 数据包解析 ---
    eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    tcph = (void *)iph + sizeof(*iph);
    if ((void *)tcph + sizeof(*tcph) > data_end) return TC_ACT_OK;
    
    // --- 检查端口 ---
    // 直接访问结构体成员，不使用BPF_CORE_READ
    target_port = bpf_ntohs(tcph->dest);
    val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) return TC_ACT_OK;

    // --- 只处理SYN包 ---
    if (!(tcph->syn && !tcph->ack)) return TC_ACT_OK;

    // --- 准备并注入Proxy Protocol头部 ---
    struct pp_v2_header pp_hdr;
    __builtin_memset(&pp_hdr, 0, sizeof(pp_hdr));
    __builtin_memcpy(pp_hdr.sig, "\r\n\r\n\0\r\nQUIT\n", 12);
    pp_hdr.ver_cmd = 0x21;
    pp_hdr.fam     = 0x11;
    pp_hdr.len     = bpf_htons(sizeof(pp_hdr.addr.ipv4));
    pp_hdr.addr.ipv4.src_addr = iph->saddr;
    pp_hdr.addr.ipv4.dst_addr = iph->daddr;
    pp_hdr.addr.ipv4.src_port = tcph->source;
    pp_hdr.addr.ipv4.dst_port = tcph->dest;

    if (bpf_skb_adjust_room(skb, sizeof(pp_hdr), BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT;

    // 注意：iph->ihl 和 tcph->doff 已经是乘以4的长度
    if (bpf_skb_store_bytes(skb, ETH_HLEN + iph->ihl * 4 + tcph->doff * 4, &pp_hdr, sizeof(pp_hdr), 0))
        return TC_ACT_SHOT;

    bpf_printk("Injected Proxy Protocol for port %d", target_port);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
