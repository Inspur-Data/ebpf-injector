//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>

char __license[] SEC("license") = "GPL";

struct toa_data {
    __u8 kind;
    __u8 len;
    __u16 port;
    __u32 ip;
} __attribute__((packed));

// BPF_CSUM_DIFF 是一个内部函数，用于计算校验和，我们需要声明它
#ifndef BPF_CSUM_DIFF_H
#define BPF_CSUM_DIFF_H
static __always_inline __s64 bpf_csum_diff(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __be32 seed) {
    return bpf_helper_func(BPF_FUNC_csum_diff, from, from_size, to, to_size, seed);
}
#endif

SEC("tc")
int inject_tcp_option(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;
    __s64 csum_diff;

    // --- 1. 初始指针和边界检查 ---
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;

    struct iphdr *iph = (void *)eth + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP) || iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph)) return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) return TC_ACT_OK;

    if (!tcph->syn) return TC_ACT_OK; // 只处理 SYN 包

    __u32 old_tcp_hdr_len = tcph->doff * 4;
    if (old_tcp_hdr_len < sizeof(*tcph)) return TC_ACT_OK;

    // --- 2. 检查是否有足够空间添加新选项 ---
    if (old_tcp_hdr_len + sizeof(struct toa_data) > 60) {
        return TC_ACT_OK; // TCP 头部最大 60 字节
    }

    // --- 3. 【读取】在修改数据包前，读取所有需要的值 ---
    __u32 old_doff = tcph->doff;
    __u32 new_doff = old_doff + (sizeof(struct toa_data) / 4);

    // --- 4. 扩展 SKB 空间 ---
    if (bpf_skb_adjust_room(skb, sizeof(struct toa_data), BPF_ADJ_ROOM_NET, 0) < 0) {
        return TC_ACT_OK;
    }

    // --- 5. 【关键】在 adjust_room 后, 必须重新加载所有指针和边界 ---
    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;
    eth      = data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;

    iph      = (void *)eth + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;

    ip_hdr_len = iph->ihl * 4; // 重新获取 ip 头长度
    if (ip_hdr_len < sizeof(*iph)) return TC_ACT_OK;

    tcph     = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) return TC_ACT_OK;

    // --- 6. 写入新的 TCP 选项 ---
    struct toa_data opt = {
        .kind = 254,
        .len  = sizeof(struct toa_data),
        .port = tcph->source,
        .ip   = iph->saddr,
    };
    if (bpf_skb_store_bytes(skb, ip_hdr_len + sizeof(*eth) + old_tcp_hdr_len, &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    // --- 7. 【安全地更新校验和】 ---
    // a. 更新 TCP 头长度 (doff)
    tcph->doff = new_doff;

    // b. 更新 IP 总长度
    __be16 new_tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + sizeof(struct toa_data));
    iph->tot_len = new_tot_len;

    // c. 更新 IP 头部校验和 (L3 csum)
    csum_diff = bpf_csum_diff(&iph->tot_len, sizeof(iph->tot_len), &new_tot_len, sizeof(new_tot_len), 0);
    bpf_l3_csum_replace(skb, ip_hdr_len + offsetof(struct iphdr, check), 0, csum_diff, 0);

    // d. 更新 TCP 校验和 (L4 csum)
    csum_diff = bpf_csum_diff(&tcph->doff, sizeof(tcph->doff), &new_doff, sizeof(new_doff), 0);
    bpf_l4_csum_replace(skb, ip_hdr_len + offsetof(struct tcphdr, check), 0, csum_diff, BPF_F_PSEUDO_HDR);

    return TC_ACT_OK;
}
