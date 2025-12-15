
//go:build ignore

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in6.h>

// [关键] go:generate 指令，用于自动从 C 代码生成 Go 代码
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_tcp_option_kern.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include

int _version SEC("version") = 1;

// IPv4 TOA (TCP Option Address) 数据结构
struct toa_v4_data {
	__u8 kind;
	__u8 len;
	__u16 port;
    __u32 ip;
};

// IPv6 TOA 数据结构
struct toa_v6_data {
	__u8 kind;
	__u8 len;
	__u16 port;
    struct in6_addr ip6;
};

// 定义一个 IPv4 TOA 选项的实例
struct toa_v4_data toav4 = {
	.kind = 254, // 自定义 TCP Option Kind
	.len = sizeof(toav4),
	.port = 8080,
	.ip = bpf_htonl(0x04040404), // 示例 IP: 4.4.4.4
};

// 定义一个 IPv6 TOA 选项的实例 (当前代码中未使用)
struct toa_v6_data toav6 = {
	.kind = 253,
	.len = sizeof(toav6),
	.port = 8080,
	.ip6 = {
		.in6_u.u6_addr32 = {
			bpf_htonl(0x20010000), 0x00,0x00, bpf_htonl(0x00008888)
		},
	},
};

// 在 TCP SYN 包中存储自定义头部选项的辅助函数
static inline void sockops_tcp_store_hdr(struct bpf_sock_ops *skops)
{
	// 确保只在 SYN 包上设置 TCP Option
	if((skops->skb_tcp_flags & 0x0002) != 0x0002) {
		bpf_printk("not a syn packet, flags: %02x", skops->skb_tcp_flags);
		return;
	}
	// 调用内核辅助函数来存储 TCP 选项
	bpf_store_hdr_opt(skops, &toav4, sizeof(toav4), 0);
}

// sockops eBPF 程序主函数
SEC("sockops")
int bpf_sockops_toa(struct bpf_sock_ops *skops)
{
	int op = (int) skops->op;

	switch(op) {
		// 对于主动建立的连接
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
		// 对于被动建立的连接
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			// 设置回调标志，告诉内核我们需要在后续写入 TCP 选项
			bpf_sock_ops_cb_flags_set(skops,
				skops->bpf_sock_ops_cb_flags |
				BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
			break;

		// 内核询问需要为 TCP 选项保留多少空间
		case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
			// 为我们的 TOA 选项保留空间
			bpf_reserve_hdr_opt(skops, sizeof(toav4), 0);
			break;

		// 内核回调此函数，让我们实际写入 TCP 选项内容
		case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
			// 调用辅助函数写入数据
			sockops_tcp_store_hdr(skops);
			bpf_printk("TOA ebpf option written successfully");
			break;
	}
	return 1;
}

// 许可证声明，对于 eBPF 程序是必需的
char _license[] SEC("license") = "GPL";
