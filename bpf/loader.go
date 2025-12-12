// 文件路径: bpf/loader.go

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_tcp_option_kern.c -- -O2 -g -Wall -Werror -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu
