//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>         // <<<--- 修正 1：添加这个头文件
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>           // 引入 offsetof

char __license[] SEC("license") = "GPL";
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

    if (iph->protocol != IPPROTO_TCP) { // 现在 IPPROTO_TCP 宏已定义
        return TC_ACT_OK;
    }

    __u32 ip_hdr_len = iph->ihl * 4;
    if(ip_hdr_len < sizeof(*iph)) { // 增加一个安全检查
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
    if (tcp_hdr_len > (60 - sizeof(struct toa_data))) {
        return TC_ACT_OK;
    }

    // 提前保存需要的信息
    __u16 source_port = tcph->source;
    __u32 source_ip   = iph->saddr;
    __u16 old_tot_len = iph->tot_len;

    // 扩展skb以容纳新的TCP选项
    if (bpf_skb_adjust_room(skb, sizeof(struct toa_data), BPF_ADJ_ROOM_NET, 0) < 0) {
        return TC_ACT_OK;
    }

    // 重新获取指针，因为 skb 可能已重新分配
    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;
    eth      = data;
    iph      = data + sizeof(*eth);
    tcph     = (void *)iph + ip_hdr_len;

    // 再次进行所有边界检查
    if (data + sizeof(*eth) + ip_hdr_len + tcp_hdr_len + sizeof(struct toa_data) > data_end) {
        return TC_ACT_OK;
    }

    // 准备要插入的TOA数据
    struct toa_data opt;
    opt.kind = 254;
    opt.len  = sizeof(struct toa_data);
    opt.port = source_port;
    opt.ip   = source_ip;

    // 将TCP选项写入到TCP头之后
    if (bpf_skb_store_bytes(skb, sizeof(*eth) + ip_hdr_len + sizeof(struct tcphdr), &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    // ----- 修正 2：更新校验和与长度 -----
    __u8 new_doff = tcph->doff + (sizeof(struct toa_data) / 4);

    // 更新 IP 头部总长度
    __u16 new_tot_len = bpf_htons(bpf_ntohs(old_tot_len) + sizeof(struct toa_data));
    bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), old_tot_len, new_tot_len, sizeof(__u16));
    bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, tot_len), &new_tot_len, sizeof(new_tot_len), 0);

    // 更新 TCP 头部数据偏移
    // 注意：doff 是一个 4-bit 的字段，直接修改它很棘手。
    // bpf_l4_csum_replace 会帮助我们处理校验和的更新。
    // 我们需要告诉它旧值和新值，但只针对 doff 所在的那 16 位。
    __u16 old_doff_flags = *((__u16*)((void*)tcph + 12)); // 获取包含 doff 和 flags 的 2 字节
    tcph->doff = new_doff;
    __u16 new_doff_flags = *((__u16*)((void*)tcph + 12));
    bpf_l4_csum_replace(skb, sizeof(*eth) + ip_hdr_len + offsetof(struct tcphdr, check), old_doff_flags, new_doff_flags, BPF_F_PSEUDO_HDR | BPF_F_HDR_FIELD_REL);

    return TC_ACT_OK;
}
