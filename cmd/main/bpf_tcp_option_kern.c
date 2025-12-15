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
int _version SEC("version") = 1;

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

    __u32 ip_hdr_len = iph->ihl * 4;
    // 确保IP头长度至少为20字节
    if (ip_hdr_len < sizeof(*iph)) {
        return TC_ACT_OK;
    }

    // 2. 确保TCP头是完整的
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) {
        return TC_ACT_OK;
    }

    // 3. 只在SYN包上添加选项
    if (!(tcph->syn)) {
        return TC_ACT_OK;
    }

    __u32 tcp_hdr_len = tcph->doff * 4;
    // 确保TCP头长度至少为20字节
    if (tcp_hdr_len < sizeof(*tcph)) {
        return TC_ACT_OK;
    }

    // 4. 检查是否有足够的空间来添加我们的选项
    if (tcp_hdr_len + sizeof(struct toa_data) > 60) {
        return TC_ACT_OK;
    }

    // 5. 扩展数据包以容纳新的TCP选项
    if (bpf_skb_adjust_room(skb, sizeof(struct toa_data), BPF_ADJ_ROOM_NET, 0) < 0) {
        return TC_ACT_OK;
    }

    // 6. bpf_skb_adjust_room会使指针失效，必须重新加载和验证
    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;
    eth      = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;

    iph      = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;

    tcph     = (void *)iph + ip_hdr_len;
    if ((void *)tcph + tcp_hdr_len > data_end) return TC_ACT_OK;

    // 7. 准备并写入我们的自定义选项
    struct toa_data opt;
    opt.kind = 254; // 自定义类型
    opt.len  = sizeof(struct toa_data);
    opt.port = tcph->source;
    opt.ip   = iph->saddr;

    if (bpf_skb_store_bytes(skb, ip_hdr_len + sizeof(*eth) + tcp_hdr_len, &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    // 8. 更新IP头和TCP头的长度和校验和
    __u32 old_iph_tot_len = iph->tot_len;
    __u32 new_iph_tot_len = bpf_htons(bpf_ntohs(old_iph_tot_len) + sizeof(struct toa_data));
    __u32 old_tcp_doff = tcph->doff;
    __u32 new_tcp_doff = old_tcp_doff + (sizeof(struct toa_data) / 4);

    // 更新IP头总长度
    bpf_l3_csum_replace(skb, (sizeof(*eth) + offsetof(struct iphdr, check)), old_iph_tot_len, new_tot_len, sizeof(__u16));
    bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, tot_len), &new_iph_tot_len, sizeof(new_iph_tot_len), 0);

    // 更新TCP头长度 (doff)
    __u32 tcp_doff_offset = sizeof(*eth) + ip_hdr_len + 12;
    __u8 new_doff_u8 = new_tcp_doff << 4;
    bpf_skb_store_bytes(skb, tcp_doff_offset, &new_doff_u8, sizeof(new_doff_u8), BPF_F_RECOMPUTE_CSUM);


    return TC_ACT_OK;
}
