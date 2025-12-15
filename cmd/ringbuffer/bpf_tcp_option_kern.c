//go:build ignore

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * go:generate
 */
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_tcp_option_kern.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include

int _version SEC("version") = 1;

/* =========================
 * TCP TOA Option 定义
 * =========================
 *
 * TCP option length 必须是 4 字节对齐
 * 本结构体大小为 8 bytes，合法
 */
struct toa_v4_data {
	__u8  kind;   /* TCP option kind */
	__u8  len;    /* option length */
	__u16 port;   /* source port */
	__u32 ip;     /* source IPv4 */
};

/* =========================
 * sockops 程序
 * =========================
 */
SEC("sockops")
int bpf_sockops_toa(struct bpf_sock_ops *skops)
{
	switch (skops->op) {

	/*
	 * 主动建立 TCP 连接（客户端）
	 * 告诉内核：我需要写 TCP option
	 */
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		bpf_sock_ops_cb_flags_set(
			skops,
			skops->bpf_sock_ops_cb_flags |
			BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG
		);
		break;

	/*
	 * 内核回调：询问 TCP option 需要的空间
	 * 这里只能 reserve，不能写
	 */
	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		bpf_reserve_hdr_opt(skops, sizeof(struct toa_v4_data), 0);
		break;

	/*
	 * 内核回调：真正写入 TCP option
	 * 此时一定是 SYN / SYN-ACK 阶段
	 */
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB: {
		struct toa_v4_data toa = {
			.kind = 254,                          /* 自定义 TOA kind */
			.len  = sizeof(struct toa_v4_data),
			.port = skops->remote_port,          /* 真实源端口 */
			.ip   = skops->remote_ip4,           /* 真实源 IPv4 */
		};

		bpf_store_hdr_opt(skops, &toa, sizeof(toa), 0);
		bpf_printk("TOA option injected: ip=%x port=%u",
			   toa.ip, bpf_ntohs(toa.port));
		break;
	}

	default:
		break;
	}

	return 1;
}

/* =========================
 * License（必须）
 * =========================
 */
char _license[] SEC("license") = "GPL";
