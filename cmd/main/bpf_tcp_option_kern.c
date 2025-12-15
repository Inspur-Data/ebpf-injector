//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

struct toa_data {
    __u8 kind;
    __u8 len;
    __u16 port;
    __u32 ip;
} __attribute__((packed));

SEC("tc")
int inject_tcp_option(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // 1. 检查数据包长度
    if (data + sizeof(*eth) > data_end) {
        return TC_ACT_OK;
    }
    // 2. 只处理IPv4
    if (eth->h_proto != __bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    // 3. 检查IP头
    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) {
        return TC_ACT_OK;
    }
    // 4. 只处理TCP
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    __u32 ip_hdr_len = iph->ihl * 4;

    // 5. 检查TCP头
    tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) {
        return TC_ACT_OK;
    }

    // 6. 只在SYN包上操作
    if (!tcph->syn) {
        return TC_ACT_OK;
    }

    // 7. 检查是否有足够空间
    if (tcph->doff * 4 > 54) {
        return TC_ACT_OK;
    }

    // 8. 扩展SKB以容纳我们的选项
    if (bpf_skb_adjust_room(skb, sizeof(struct toa_data), BPF_ADJ_ROOM_NET, 0) < 0) {
        return TC_ACT_OK;
    }

    // 9. 重新获取指针 (bpf_skb_adjust_room会使它们失效)
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    iph = data + sizeof(*eth);
    tcph = (void *)iph + (iph->ihl * 4);

    // 10. 再次进行边界检查
    if ((void *)tcph + (tcph->doff * 4) > data_end) {
        return TC_ACT_OK;
    }

    // 11. 准备并写入我们的自定义选项
    struct toa_data opt;
    opt.kind = 254; // 自定义类型
    opt.len = sizeof(struct toa_data);
    opt.port = tcph->source;
    opt.ip   = iph->saddr;

    if (bpf_skb_store_bytes(skb, sizeof(*eth) + (iph->ihl * 4) + sizeof(struct tcphdr), &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    // 12. 更新TCP头长度 (doff) 和 IP头总长度 (tot_len)
    __u32 old_len = iph->tot_len;
    __u32 new_len = bpf_htons(bpf_ntohs(iph->tot_len) + sizeof(struct toa_data));
    __u8 old_doff = tcph->doff;
    __u8 new_doff = tcph->doff + (sizeof(struct toa_data) / 4);

    bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), old_len, new_len, 2);
    bpf_l4_csum_replace(skb, sizeof(*eth) + (iph->ihl * 4) + offsetof(struct tcphdr, check), bpf_htons(old_doff << 12), bpf_htons(new_doff << 12), 2);

    bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, tot_len), &new_len, sizeof(new_len), 0);
    bpf_skb_store_bytes(skb, sizeof(*eth) + (iph->ihl * 4) + offsetof(struct tcphdr, doff), &new_doff, sizeof(new_doff), 0);

    return TC_ACT_OK;
}
