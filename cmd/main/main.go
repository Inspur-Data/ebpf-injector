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
		log.Fatal(err)
	}

	// 加载 eBPF 对象 (这些函数由 go generate 自动创建在同一个包中)
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

		// 为每个接口附加一个 clsact qdisc (排队规则)
		// 这是挂载 TC 类型 eBPF 程序的先决条件
		qdisc := &link.TcQdisc{
			ifindex: i.Index,
			Handle:  link.MakeHandle(0xffff, 0),
			Parent:  link.HANDLE_CLSACT,
		}
		if err := qdisc.Create(); err != nil {
			log.Printf("could not create qdisc on interface %s: %v.", i.Name, err)
			continue
		}
		defer qdisc.Close() // 确保qdisc在程序退出时被清理

		// 附加 eBPF 程序到 ingress (入口) 流量
		// 注意：C 文件中的函数名 inject_tcp4opt 会被 bpf2go 转换为 BpfInjectTcp4opt
		ingress, err := link.AttachTCX(link.TCXOptions{
			Program:   objs.BpfProgs.InjectTcp4opt,
			Attach:    ebpf.AttachTCXIngress,
			Interface: i.Index,
		})
		if err != nil {
			log.Fatalf("could not attach TC program to ingress on interface %q: %s", i.Name, err)
		}
		links = append(links, ingress) // 添加到列表以便稍后清理

		// 附加 eBPF 程序到 egress (出口) 流量
		egress, err := link.AttachTCX(link.TCXOptions{
			Program:   objs.BpfProgs.InjectTcp4opt, // 同一个程序
			Attach:    ebpf.AttachTCXEgress,
			Interface: i.Index,
		})
		if err != nil {
			log.Fatalf("could not attach TC program to egress on interface %q: %s", i.Name, err)
		}
		links = append(links, egress) // 添加到列表以便稍后清理

		log.Printf("Attached TC program to interface %q (index %d)", i.Name, i.Index)
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