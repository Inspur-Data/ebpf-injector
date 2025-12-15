//go:build ignore

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

    // 1. 确保以太网头和IP头是完整的
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK; // 只处理IPv4
    }

    struct iphdr *iph = data + sizeof(*eth);
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK; // 只处理TCP
    }

    // 2. 确保TCP头是完整的
    __u32 ip_hdr_len = iph->ihl * 4;
    if(ip_hdr_len < sizeof(*iph)) { // 安全检查
        return TC_ACT_OK;
    }

    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) {
        return TC_ACT_OK;
    }

    // 3. 只在SYN包上添加选项
    if (!(tcph->syn)) {
        return TC_ACT_OK;
    }

    __u32 tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < sizeof(*tcph)) {
        return TC_ACT_OK;
    }

    // 4. 检查是否有足够的空间来添加我们的选项 (TCP头部最大60字节)
    if (tcp_hdr_len + sizeof(struct toa_data) > 60) {
        return TC_ACT_OK;
    }

    // 5. 提前保存需要的信息
    __u16 source_port = tcph->source;
    __u32 source_ip   = iph->saddr;
    __u16 old_tot_len = iph->tot_len;

    // 6. 扩展SKB以容纳新的TCP选项
    if (bpf_skb_adjust_room(skb, sizeof(struct toa_data), BPF_ADJ_ROOM_NET, 0) < 0) {
        return TC_ACT_OK;
    }

    // 7. 重新获取指针，因为 bpf_skb_adjust_room 会使其失效
    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;

    eth = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;

    iph = data + sizeof(*eth);
    if ((void *)iph + ip_hdr_len > data_end) return TC_ACT_OK;

    tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + tcp_hdr_len > data_end) return TC_ACT_OK;

    // 8. 准备并写入我们的自定义选项
    struct toa_data opt;
    opt.kind = 254; // 自定义类型
    opt.len  = sizeof(struct toa_data);
    opt.port = source_port; // 使用之前保存的值
    opt.ip   = source_ip;   // 使用之前保存的值

    if (bpf_skb_store_bytes(skb, sizeof(*eth) + ip_hdr_len + sizeof(struct tcphdr), &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    // 9. 更新TCP头长度 (doff) 和 IP头总长度 (tot_len)
    __u8 new_doff = tcph->doff + (sizeof(struct toa_data) / 4);

    // 更新IP头总长度
    __be16 new_tot_len = bpf_htons(bpf_ntohs(old_tot_len) + sizeof(struct toa_data));
    bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), old_tot_len, new_tot_len, sizeof(__u16));
    bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, tot_len), &new_tot_len, sizeof(new_tot_len), 0);

    // 更新TCP头长度 (doff)
    // BPF_F_RECOMPUTE_CSUM 会让内核自动重新计算校验和
    bpf_skb_store_bytes(skb, sizeof(*eth) + ip_hdr_len + 12, &new_doff, sizeof(new_doff), BPF_F_RECOMPUTE_CSUM);

    return TC_ACT_OK;
}

