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

// 自定义TCP选项
struct toa_data {
    __u8 kind;
    __u8 len;
    __u16 port;
    __u32 ip;
} __attribute__((packed));

SEC("tc")
int inject_tcp_option(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) {
        return TC_ACT_OK;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph)) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) {
        return TC_ACT_OK;
    }

    if (!(tcph->syn)) {
        return TC_ACT_OK;
    }

    __u32 tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < sizeof(*tcph)) {
        return TC_ACT_OK;
    }

    if (tcp_hdr_len + sizeof(struct toa_data) > 60) {
        return TC_ACT_OK;
    }

    __u16 source_port = tcph->source;
    __u32 source_ip   = iph->saddr;
    __u16 old_tot_len = iph->tot_len;

    if (bpf_skb_adjust_room(skb, sizeof(struct toa_data), BPF_ADJ_ROOM_NET, 0) < 0) {
        return TC_ACT_OK;
    }

    // --- 关键修正区域 START ---
    // 在 bpf_skb_adjust_room 之后, 必须重新加载所有指针和长度

    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;
    eth      = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;

    iph      = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;

    // 【【【 核心修正 】】】
    // 必须重新计算 ip_hdr_len，因为 iph 指针已经被重新加载
    ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph)) {
        return TC_ACT_OK;
    }

    tcph     = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) return TC_ACT_OK;
    // --- 关键修正区域 END ---

    struct toa_data opt;
    opt.kind = 254;
    opt.len  = sizeof(struct toa_data);
    opt.port = source_port;
    opt.ip   = source_ip;

    if (bpf_skb_store_bytes(skb, sizeof(*eth) + ip_hdr_len + tcp_hdr_len, &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    __u8 new_doff = tcph->doff + (sizeof(struct toa_data) / 4);

    // 注意: bpf_l3_csum_replace 和 bpf_skb_store_bytes 已经隐式处理了 tot_len,
    // 但为了代码清晰和可移植性，我们手动更新
    __be16 new_tot_len = bpf_htons(bpf_ntohs(old_tot_len) + sizeof(struct toa_data));
    bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), old_tot_len, new_tot_len, sizeof(__u16));
    bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, tot_len), &new_tot_len, sizeof(new_tot_len), 0);

    bpf_skb_store_bytes(skb, sizeof(*eth) + ip_hdr_len + 12, &new_doff, sizeof(new_doff), BPF_F_RECOMPUTE_CSUM);

    return TC_ACT_OK;
}
