//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;

// 自定义TCP选项结构
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
    struct iphdr *iph;
    struct tcphdr *tcph;
    __u32 ip_hdr_len, tcp_hdr_len, ip_total_len;
    __u16 source_port;
    __u32 source_ip;

    // 1. 检查以太网头部
    if (data + sizeof(*eth) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK; // 只处理IPv4
    }

    // 2. 检查IP头部
    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) {
        return TC_ACT_OK;
    }
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK; // 只处理TCP
    }
    ip_hdr_len = iph->ihl * 4;

    // 3. 检查TCP头部
    tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) {
        return TC_ACT_OK;
    }

    // 4. 只处理SYN包
    if (!(tcph->syn)) {
        return TC_ACT_OK;
    }

    // 5. 检查TCP选项空间是否足够 (TCP头部最大60字节)
    tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len > (60 - sizeof(struct toa_data))) {
        return TC_ACT_OK;
    }

    // 6. 安全地读取源IP和源端口
    source_ip = iph->saddr;
    source_port = tcph->source;
    ip_total_len = iph->tot_len; // 保存旧的总长度

    // 7. 调整skb大小，为新的TCP选项腾出空间
    if (bpf_skb_adjust_room(skb, sizeof(struct toa_data), BPF_ADJ_ROOM_NET, 0)) {
        return TC_ACT_OK;
    }

    // 8. **非常重要**：`bpf_skb_adjust_room` 会使之前的指针失效。必须重新验证所有指针。
    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;

    eth = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;

    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;

    // 再次检查IP头长度，防止被篡改
    if(iph->ihl * 4 < sizeof(struct iphdr)) return TC_ACT_OK;
    ip_hdr_len = iph->ihl * 4;

    tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) return TC_ACT_OK;

    // 再次检查TCP头长度
    tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) return TC_ACT_OK;


    // 9. 准备要插入的TCP选项
    struct toa_data opt;
    opt.kind = 254; // Experimental TCP option
    opt.len = sizeof(struct toa_data);
    opt.port = source_port; // 使用之前保存的值
    opt.ip   = source_ip;    // 使用之前保存的值

    // 10. 写入新的TCP选项
    // 偏移量 = L2头长 + IP头长 + TCP标准头长
    if (bpf_skb_store_bytes(skb, sizeof(*eth) + ip_hdr_len + sizeof(struct tcphdr), &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    // 11. 更新TCP头长度 (data offset)
    __u8 new_doff = tcph->doff + (sizeof(opt) / 4);
    if (bpf_l4_csum_replace(skb, sizeof(*eth) + ip_hdr_len + offsetof(struct tcphdr, check), bpf_htons(tcph->doff << 12), bpf_htons(new_doff_val << 12), 2) < 0) {
        return TC_ACT_OK;
    }

    // 12. 更新IP总长度
    __be16 new_tot_len = bpf_htons(bpf_ntohs(ip_total_len) + sizeof(struct toa_data));
    if (bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), ip_total_len, new_tot_len, sizeof(__be16)) < 0) {
        return TC_ACT_OK;
    }

    // 13. 直接修改头部的长度字段
    // 这一步对于某些内核版本是必需的，以确保数据包在后续处理中被正确解析
    bpf_skb_store_bytes(skb, sizeof(*eth) + ip_hdr_len + offsetof(struct tcphdr, doff), &new_doff, sizeof(new_doff), 0);
    bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, tot_len), &new_tot_len, sizeof(new_tot_len), 0);

    return TC_ACT_OK;
}
