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

SEC("tc")
int inject_tcp_option(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    // --- 初始指针和边界检查 ---
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph)) return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end) return TC_ACT_OK;
    if (!(tcph->syn)) return TC_ACT_OK;

    // --- 【阶段一：读取】在修改数据包前，读取所有需要的值 ---
    __u32 old_tcp_hdr_len = tcph->doff * 4;
    if (old_tcp_hdr_len < sizeof(*tcph)) return TC_ACT_OK;
    if (old_tcp_hdr_len + sizeof(struct toa_data) > 60) return TC_ACT_OK;

    __u16 source_port = tcph->source;
    __u32 source_ip   = iph->saddr;
    __be16 old_tot_len_be = iph->tot_len;

    // 【【 核心修正：正确读取位域 】】
    // 1. 计算包含 doff 的16位字段的偏移量 (硬编码12，因为 tcphdr 结构固定)
    int doff_flags_offset = sizeof(*eth) + ip_hdr_len + 12;

    // 2. 读取这个16位的字段
    __be16 old_doff_flags_word_be;
    if (bpf_skb_load_bytes(skb, doff_flags_offset, &old_doff_flags_word_be, sizeof(old_doff_flags_word_be)) < 0) {
        return TC_ACT_OK;
    }

    // --- 【阶段二：写入】计算新值，并执行所有修改操作 ---

    // 1. 准备要写入的新选项
    struct toa_data opt;
    opt.kind = 254;
    opt.len  = sizeof(struct toa_data);
    opt.port = source_port;
    opt.ip   = source_ip;

    // 2. 计算新的 doff 值
    __u16 old_doff_flags_word_host = bpf_ntohs(old_doff_flags_word_be);
    __u8 old_doff = (old_doff_flags_word_host >> 12); // doff 在高4位
    __u8 new_doff_val = old_doff + (sizeof(struct toa_data) / 4);

    // 3. 构造包含新 doff 的16位字段
    __u16 new_doff_flags_word_host = (old_doff_flags_word_host & 0x0FFF) | (new_doff_val << 12);
    __be16 new_doff_flags_word_be = bpf_htons(new_doff_flags_word_host);

    // 4. 准备新的 IP 总长度
    __be16 new_tot_len_be = bpf_htons(bpf_ntohs(old_tot_len_be) + sizeof(struct toa_data));

    // 5. 扩展 SKB 空间
    if (bpf_skb_adjust_room(skb, sizeof(struct toa_data), BPF_ADJ_ROOM_NET, 0) < 0) {
        return TC_ACT_OK;
    }

    // 6. 在 adjust_room 后, 必须重新验证指针才能安全地写回
    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;
    eth      = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;
    iph      = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return TC_ACT_OK;
    __u32 new_ip_hdr_len = iph->ihl * 4; // 重新获取 ip 头长度
    if (new_ip_hdr_len < sizeof(*iph)) return TC_ACT_OK;

    // 7. 写入新的 TCP 选项
    if (bpf_skb_store_bytes(skb, sizeof(*eth) + new_ip_hdr_len + old_tcp_hdr_len, &opt, sizeof(opt), 0) < 0) {
        return TC_ACT_OK;
    }

    // 8. 更新 IP 头部（总长度和校验和）
    bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), old_tot_len_be, new_tot_len_be, sizeof(__u16));
    bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, tot_len), &new_tot_len_be, sizeof(new_tot_len_be), 0);

    // 9. 【【 核心修正：正确写回位域 】】
    //    写回包含新 doff 的整个16位字段，并让内核重算校验和
    if (bpf_skb_store_bytes(skb, sizeof(*eth) + new_ip_hdr_len + 12, &new_doff_flags_word_be, sizeof(new_doff_flags_word_be), BPF_F_RECOMPUTE_CSUM) < 0) {
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}
