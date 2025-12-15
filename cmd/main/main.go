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
	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_tcp_option_kern.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include
func main() {
	// 订阅停止信号
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 移除内存锁定限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock limit:", err)
	}

	// 加载 eBPF 对象 (这些函数由 go:generate 自动创建在同一个包中)
	// 这个结构是 bpf2go 默认生成的
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

		// 附加 TC qdisc (排队规则)
		// 这是挂载 TC BPF 程序的先决条件
		qdisc, err := link.AttachNewNetem(link.NetworkInterface{Index: i.Index})
		if err != nil {
			log.Fatalf("could not attach TCNETEM qdisc to interface %s: %v", i.Name, err)
		}
		defer qdisc.Close() // 确保qdisc在程序退出时被清理

		// 附加 eBPF 程序到 egress (出口) 流量
		// 注意：C 文件中的函数名 inject_tcp4opt 会被 bpf2go 自动转换为 BpfInjectTcp4opt
		l, err := link.AttachTC(link.TCOptions{
			Program:   objs.InjectTcp4opt, // 修正：直接访问 objs.InjectTcp4opt
			Interface: i.Index,
			Attach:    link.TCEgress, // 附加到出口
		})
		if err != nil {
			log.Fatalf("could not attach TC program to egress on interface %q: %s", i.Name, err)
		}
		links = append(links, l) // 添加到列表以便稍后清理

		log.Printf("Attached TC program to egress of interface %q (index %d)", i.Name, i.Index)
	}

	// 如果没有成功附加到任何接口，则报错退出
	if len(links) == 0 {
		log.Fatalf("Could not attach to any network interfaces")
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
	log.Println("Received shutdown signal, detaching programs and exiting.")
}