#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#include "bpf_helpers.h" // 我们将使用libbpf-bootstrap中的头文件

// Proxy Protocol v2 二进制格式
struct pp_v2_header {
    __u8 sig[12];
    __u8 ver_cmd;
    __u8 fam;
    __be16 len;
    union {
        struct {
            __be32 src_addr;
            __be32 dst_addr;
            __be16 src_port;
            __be16 dst_port;
        } ipv4;
        struct {
            __u8 src_addr[16];
            __u8 dst_addr[16];
            __be16 src_port;
            __be16 dst_port;
        } ipv6;
    } addr;
}


// 定义一个BPF Map，用于从用户态接收要处理的端口号
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16); // port
    __type(value, __u8); // value (e.g., 1 for enabled)
} ports_map SEC(".maps");

SEC("tc")
int tc_proxy_protocol(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    __u16 target_port;
    __u8 *val;

    // 1. 基础检查：确保是IP包
    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 2. 解析IP头
    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // 3. 解析TCP头
    tcph = (void *)iph + sizeof(*iph);
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return TC_ACT_OK;
    
    // 4. 检查是否是我们需要处理的目标端口
    target_port = bpf_ntohs(tcph->dest);
    val = bpf_map_lookup_elem(&ports_map, &target_port);
    if (!val || *val == 0) {
        // 如果端口不在map中，或者值为0，则直接放行
        return TC_ACT_OK;
    }

    // 5. 只处理TCP三次握手的第一个包 (SYN包)
    if (!(tcph->syn && !tcph->ack))
        return TC_ACT_OK;

    // 6. 准备Proxy Protocol V2头部
    struct pp_v2_header pp_hdr;
    __builtin_memset(&pp_hdr, 0, sizeof(pp_hdr));
    __builtin_memcpy(pp_hdr.sig, "\r\n\r\n\0\r\nQUIT\n", 12);
    pp_hdr.ver_cmd = 0x21; // version 2, command PROXY
    pp_hdr.fam = 0x11;     // AF_INET, TCP
    pp_hdr.len = bpf_htons(sizeof(pp_hdr.addr.ipv4));
    pp_hdr.addr.ipv4.src_addr = iph->saddr;
    pp_hdr.addr.ipv4.dst_addr = iph->daddr;
    pp_hdr.addr.ipv4.src_port = tcph->source;
    pp_hdr.addr.ipv4.dst_port = tcph->dest;

    // 7. 为Proxy Protocol头部腾出空间
    if (bpf_skb_adjust_room(skb, sizeof(pp_hdr), BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_SHOT; // 如果失败，丢弃该包

    // 8. 将Proxy Protocol头部写入数据包
    if (bpf_skb_store_bytes(skb, ETH_HLEN + iph->ihl * 4 + tcph->doff * 4, &pp_hdr, sizeof(pp_hdr), 0))
        return TC_ACT_SHOT; // 如果失败，丢弃该包

    bpf_printk("Injected Proxy Protocol for port %d\n", target_port);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
