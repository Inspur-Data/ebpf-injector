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
const (
	cgroupPath = "/sys/fs/cgroup" // 虽然TC模式不直接用，但保留无害
)

func main() {
	// 订阅停止信号
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 移除内存锁定限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock limit: ", err)
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

	var links []link.Link

	// 遍历所有网络接口
	for _, iface := range ifaces {
		// 忽略 loopback 和没有启动的接口
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(iface.Name, "veth") {
			continue
		}

		// 为每个接口附加一个 clsact qdisc (排队规则)
		qdisc, err := link.AttachNewNetem(link.NetworkInterface{Index: iface.Index})
		if err != nil {
			log.Printf("could not attach TCNETEM qdisc to interface %s: %v. Skipping.", iface.Name, err)
			continue
		}
		defer qdisc.Close()

		// [最终核心修正]
		// 正确的程序名称是 objs.BpfInjectTcpOption
		l, err := link.AttachTC(link.TCOptions{
			Program:   objs.BpfInjectTcpOption, // <--- 这里是修正的地方
			Interface: iface.Index,
			Attach:    link.TCEgress,
		})
		if err != nil {
			log.Fatalf("could not attach TC program to egress of interface %q: %s", iface.Name, err)
		}
		links = append(links, l)

		log.Printf("Attached TC program to egress of interface %q", iface.Name)
	}

	if len(links) == 0 {
		log.Fatalf("Could not attach to any suitable network interfaces")
	}

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