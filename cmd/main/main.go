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
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// 获取所有网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("failed to get network interfaces: %v", err)
	}

	// 遍历所有网络接口
	for _, i := range ifaces {
		// 忽略本地回环和虚拟接口
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || strings.HasPrefix(i.Name, "veth") {
			continue
		}

		// 为每个接口附加qdisc
		qdisc := &link.TcQdisc{
			ifindex: i.Index,
			Handle:  0xffff,
			Parent:  link.HANDLE_CLSACT,
		}
		if err := qdisc.Create(); err != nil {
			log.Printf("failed to create qdisc on %s: %v", i.Name, err)
			continue
		}

		// 附加eBPF程序到ingress (入口)
		l, err := link.AttachTC(link.TCOptions{
			Program:   objs.InjectTcp4opt, // 函数名来自 C 代码: inject_tcp4opt
			Interface: i.Index,
			Direction: link.TC_INGRESS,
		})
		if err != nil {
			log.Fatalf("could not attach TC program to interface %q: %s", i.Name, err)
		}
		defer l.Close()

		// 附加eBPF程序到egress (出口)
		l, err = link.AttachTC(link.TCOptions{
			Program:   objs.InjectTcp4opt, // 同一个程序
			Interface: i.Index,
			Direction: link.TC_EGRESS,
		})
		if err != nil {
			log.Fatalf("could not attach TC program to interface %q: %s", i.Name, err)
		}
		defer l.Close()


		log.Printf("Attached TC program to interface %q", i.Name)
	}

	log.Println("Successfully attached eBPF program. Press Ctrl-C to exit.")

	// 等待退出信号
	<-stopper
	log.Println("Received shutdown signal, exiting...")
}