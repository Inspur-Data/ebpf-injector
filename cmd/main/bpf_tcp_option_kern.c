//go:build ignore

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

// 自定义的TCP选项结构
// 使用 __attribute__((packed)) 确保没有额外的内存对齐填充
struct toa_data {
    __u8 kind;
    __u8 len;
    __u16 port;
    __u32 ip;
} __attribute__((packed));

// TC (Traffic Control) eBPF 程序
// 'SEC("tc")' 告诉编译器将这段代码放入一个名为 "tc" 的 ELF section 中
SEC("tc")
int inject_tcp_option(struct __sk_buff *skb) {
    // 获取数据包的起始和结束地址
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // ----------------- 1. 解析数据包头部 -----------------

    // 首先，确保有足够的空间存放以太网头
    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK; // 数据包太小，直接放行
    }
    struct ethhdr *eth = data;

    // 只处理 IPv4 流量 (EtherType 0x0800)
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    // 移动指针到 IP 头部
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) {
        return TC_ACT_OK; // 数据包太小，没有完整的IP头
    }

    // 只处理 TCP 流量 (IP Protocol 6)
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    // 计算 IP 头部长度 (IHL 字段 * 4 字节)
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph)) { // 安全检查
        return TC_ACT_OK;
    }

    // 移动指针到 TCP 头部
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) {
        return TC_ACT_OK; // 数据包太小，没有完整的TCP头
    }

    // ----------------- 2. 检查是否是 SYN 包 -----------------

    // 我们只想在 TCP 连接的第一个包（SYN 包）中插入选项
    if (!(tcph->syn)) {
        return TC_ACT_OK; // 如果不是SYN包，直接放行
    }

    // ----------------- 3. 准备和插入 TCP 选项 -----------------

    // TCP 头部长度（Data Offset 字段 * 4 字节）
    __u32 tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < sizeof(*tcph)) {
        return TC_ACT_OK; // 畸形包
    }

    // TCP 头部最大为60字节。检查是否有足够空间添加我们的选项
    if (tcp_hdr_len + sizeof(struct toa_data) > 60) {
        return TC_ACT_OK; // 空间不足，放弃插入
    }

    // 提前保存原始IP和端口，因为后续操作可能使指针失效
    __u32 source_ip   = iph->saddr;
    __u16 source_port = tcph->source;
    __u16 old_tot_len = iph->tot_len;

    // 关键步骤: 扩展数据包(skb)以容纳我们的新选项
    // BPF_ADJ_ROOM_NET 表示在网络层和传输层之间增加空间
    if (bpf_skb_adjust_room(skb, sizeof(struct toa_data), BPF_ADJ_ROOM_NET, 0) < 0) {
        return TC_ACT_OK;
    }

    // bpf_skb_adjust_room 会使之前的指针失效，必须重新获取和验证
    data      = (void *)(long)skb->data;
    data_end  = (void *)(long)skb->data_end;
    eth       = data;
    iph       = data + sizeof(*eth);
    tcph      = (void *)iph + ip_hdr_len;

    // 再次进行所有边界检查，确保内存安全
    if ((void *)tcph + tcp_hdr_len > data_end) {
        return TC_ACT_OK;
    }

    // 准备要写入的自定义选项数据
    struct toa_data opt;
    opt.kind = 254; // 自定义选项类型 (254, 实验性)
    opt.len  = sizeof(struct toa_data);
    opt.port = source_port;
    opt.ip   = source_ip;

    // 将选项数据写入到 TCP 头部中，紧跟在标准 TCP 头之后
    if (bpf_skb_store_bytes(skb, sizeof(*eth) + ip_hdr_len + sizeof(struct tcphdr), &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    // ----------------- 4. 更新头部字段和校验和 -----------------

    // 计算新的 TCP 头部长度 (doff 是以4字节为单位的)
    __u8 new_doff = tcph->doff + (sizeof(struct toa_data) / 4);

    // 计算新的 IP 包总长度 (字节序转换)
    __be16 new_tot_len = bpf_htons(bpf_ntohs(old_tot_len) + sizeof(struct toa_data));

    // 更新 IP 头的校验和
    bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), old_tot_len, new_tot_len, sizeof(__u16));

    // 更新 IP 头的总长度字段
    bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, tot_len), &new_tot_len, sizeof(new_tot_len), 0);

    // 更新 TCP 头的 doff 字段，并让内核重新计算 TCP 校验和
    bpf_skb_store_bytes(skb, sizeof(*eth) + ip_hdr_len + 12, &new_doff, sizeof(new_doff), BPF_F_RECOMPUTE_CSUM);

    return TC_ACT_OK;
}
