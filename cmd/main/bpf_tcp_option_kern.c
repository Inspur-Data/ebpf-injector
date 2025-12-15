//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h> 

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;

// 自定义的TCP选项结构
struct tcp_option {
    __u8 kind;
    __u8 len;
    __u16 port;
    __u32 ip;
} __attribute__((packed));

// TC程序，用于在出向（egress）流量上注入TCP选项
SEC("tc")
int inject_tcp4opt(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 ip_hdr_len = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;

    // 我们只在SYN包上添加选项
    if (!(tcph->syn))
        return TC_ACT_OK;

    // 检查TCP头部是否有足够空间添加选项
    if (tcph->doff * 4 > 60 - sizeof(struct tcp_option)) {
        return TC_ACT_OK;
    }

    // 调整skb大小，为新的TCP选项腾出空间
    if (bpf_skb_adjust_room(skb, sizeof(struct tcp_option), BPF_ADJ_ROOM_NET, 0)) {
        return TC_ACT_OK;
    }

    // 重新获取数据指针，因为skb可能已经重新分配
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    iph = (struct iphdr *)(eth + 1);
    tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);

    // 检查新的边界
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return TC_ACT_OK;

    // 准备要插入的TCP选项
    struct tcp_option opt;
    opt.kind = 254; // 自定义TCP选项类型
    opt.len = sizeof(struct tcp_option);
    // 注意：在TC hook点，skb->remote_ip4 和 skb->remote_port 通常不可靠
    // 我们应该使用IP和TCP头中的信息
    opt.port = tcph->source;
    opt.ip = iph->saddr;

    // 将TCP选项插入到TCP头之后
    if (bpf_skb_store_bytes(skb, sizeof(*eth) + ip_hdr_len + sizeof(*tcph), &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    // 更新TCP头长度 (doff)
    tcph->doff += sizeof(struct tcp_option) / 4;

    // 重新计算IP和TCP的校验和
    __u32 old_iph_tot_len = iph->tot_len;
    __u32 new_iph_tot_len = bpf_htons(bpf_ntohs(old_iph_tot_len) + sizeof(struct tcp_option));
    bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), old_iph_tot_len, new_iph_tot_len, 2);

    bpf_l4_csum_replace(skb, sizeof(*eth) + ip_hdr_len + offsetof(struct tcphdr, check), 0, bpf_htons(sizeof(struct tcp_option)), 0);

    return TC_ACT_OK;
}
