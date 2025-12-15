package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)
// go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_tcp_option_kern.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include
func main() {
	// 订阅停止信号
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 移除内存锁定限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock limit: ", err)
	}

	// 加载eBPF对象 (这些函数由go:generate自动创建在同一个包中)
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// 获取所有网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("failed to get network interfaces: %v", err)
	}

	var links []link.Link

	// 遍历所有网络接口
	for _, i := range ifaces {
		// 忽略 loopback 和没有启动的接口
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || strings.HasPrefix(i.Name, "veth") {
			continue
		}

		// 附加 qdisc (排队规则)
		qdisc, err := link.AttachNewNetem(link.NetworkInterface{Index: i.Index})
		if err != nil {
			log.Printf("could not attach TCNETEM qdisc to interface %s: %v", i.Name, err)
			continue
		}
		defer qdisc.Close() // 确保qdisc在程序退出时被清理

		// 附加 TC 程序到 egress (出口)
		// 函数名 InjectTcpOption 是从C代码中的 inject_tcp_option 自动生成的
		l, err := link.AttachTC(link.TCOptions{
			Program:   objs.InjectTcpOption, // 直接访问
			Interface: i.Index,
			Attach:    link.TCEgress,
		})
		if err != nil {
			log.Fatalf("could not attach TC program to egress of interface %q: %s", i.Name, err)
		}
		links = append(links, l) // 添加到列表以便稍后清理

		log.Printf("Attached TC program to egress of interface %q", i.Name)
	}

	if len(links) == 0 {
		log.Fatalf("Could not attach to any suitable network interfaces")
	}

	// 在程序退出时，确保所有 BPF 链接都被正确关闭
	defer func() {
		for _, l := range links {
			if err := l.Close(); err != nil {
				log.Printf("error closing link: %v", err)
			}
		}
	}()

	log.Println("Successfully attached eBPF programs. Press Ctrl-C to exit and detach.")
	<-stopper
	log.Println("Received shutdown signal, cleaning up and exiting.")
}