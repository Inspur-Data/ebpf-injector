//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define TC_ACT_OK 0

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;

// 我们将在TCP选项中插入的自定义结构
// 确保它是字节对齐的
struct toa_data {
    __u8 kind;
    __u8 len;
    __u16 port;
    __u32 ip;
} __attribute__((packed));

SEC("tc")
int toa_inserter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 1. L2/Ethernet
    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK; // 只处理IPv4
    }

    // 2. L3/IP
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)iph + sizeof(*iph) > data_end) {
        return TC_ACT_OK;
    }
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK; // 只处理TCP
    }
    __u32 ip_hdr_len = iph->ihl * 4;

    // 3. L4/TCP
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) {
        return TC_ACT_OK;
    }

    // 只处理SYN包
    if (!(tcph->syn)) {
        return TC_ACT_OK;
    }

    // TCP头部长度（以4字节为单位），Data Offset
    __u32 tcp_hdr_len = tcph->doff * 4;

    // 检查是否有足够的空间添加选项 (TCP头部最大60字节)
    if (tcp_hdr_len > (60 - sizeof(struct toa_data))) {
        return TC_ACT_OK;
    }

    // 准备要插入的TOA数据
    struct toa_data opt;
    opt.kind = 254; // 自定义TCP选项类型
    opt.len = sizeof(struct toa_data);
    opt.port = bpf_ntohs(tcph->source); // 转换为主机字节序
    opt.ip = iph->saddr; // IP已经是网络字节序

    // 扩展数据包以容纳新的TCP选项
    // BPF_ADJ_ROOM_NET 表示在网络层头和传输层头之间增加空间
    if (bpf_skb_adjust_room(skb, sizeof(struct toa_data), BPF_ADJ_ROOM_NET, 0) < 0) {
        return TC_ACT_OK;
    }

    // bpf_skb_adjust_room 可能会让指针失效，所以需要重新获取
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    iph = data + sizeof(*eth);
    tcph = (void *)iph + ip_hdr_len;

    // 将选项数据写入
    if (bpf_skb_store_bytes(skb, ip_hdr_len + sizeof(struct tcphdr), &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    // 更新TCP头长度
    __u32 new_doff = (tcp_hdr_len + sizeof(opt)) / 4;
    bpf_l4_csum_replace(skb, ip_hdr_len + offsetof(struct tcphdr, check),
                        (__be16)tcph->doff << 12, (__be16)new_doff << 12, 2);
    bpf_l3_csum_replace(skb, offsetof(struct iphdr, check),
                        bpf_htons(iph->tot_len), bpf_htons(bpf_ntohs(iph->tot_len) + sizeof(opt)), 2);

    iph->tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + sizeof(opt));
    tcph->doff = new_doff;

    return TC_ACT_OK;
}
