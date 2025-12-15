package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_tcp_option_kern.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include

func main() {
	// 订阅停止信号
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 移除内存锁定限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 加载 eBPF 对象
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// 获取所有网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("failed to get network interfaces: %v", err)
	}

	var links []link.Link

	// 将 TC 程序附加到所有物理网络接口
	for _, iface := range ifaces {
		// 忽略回环和虚拟接口
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 附加到入口 (ingress) 流量
		l, err := link.AttachTCX(link.TCXOptions{
			Program:   objs.ToaInserter, // 函数名会从 bpf_tcp_option_kern.c 中的 toa_inserter 自动生成
			Attach:    ebpf.AttachTCXIngress,
			Interface: iface.Index,
		})
		if err != nil {
			log.Printf("could not attach TC program to interface %q: %s", iface.Name, err)
			continue // 继续尝试下一个接口
		}
		links = append(links, l)
		log.Printf("Attached TC program to interface %q (index %d)", iface.Name, iface.Index)
	}

	// 如果没有成功附加到任何接口，则退出
	if len(links) == 0 {
		log.Fatalf("Could not attach to any network interfaces")
	}

	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	log.Println("Successfully attached eBPF program. Press Ctrl-C to exit and detach.")
	<-stopper
	log.Println("Exiting...")
}
