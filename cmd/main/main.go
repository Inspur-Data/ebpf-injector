// 文件路径: cmd/main/main.go
package main

import (
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

// go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_tcp_option_kern.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include

func main() {
	log.Println("Starting eBPF TOA injector...")

	// 订阅停止信号
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 获取所有网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to get network interfaces: %v", err)
	}

	var attachedInterfaces []string

	// 遍历所有网络接口
	for _, iface := range ifaces {
		// 忽略 loopback、down状态的接口，以及常见的虚拟网卡
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(iface.Name, "veth") || strings.HasPrefix(iface.Name, "docker") {
			continue
		}

		log.Printf("Attempting to attach to interface %s...", iface.Name)

		// 1. 清理旧的 qdisc (如果存在)，确保环境干净
		exec.Command("tc", "qdisc", "del", "dev", iface.Name, "clsact").Run()

		// 2. 添加 clsact qdisc (这是挂载TC BPF程序的先决条件)
		cmdAddQdisc := exec.Command("tc", "qdisc", "add", "dev", iface.Name, "clsact")
		if out, err := cmdAddQdisc.CombinedOutput(); err != nil {
			log.Printf("Failed to add qdisc to interface %s: %v. Output: %s", iface.Name, err, string(out))
			continue
		}

		// 3. 附加 BPF 程序到 egress hook (出向流量)
		//    我们直接使用 bpf2go 生成的 .o 文件
		cmdAttachEgress := exec.Command("tc", "filter", "add", "dev", iface.Name, "egress", "bpf", "direct-action", "object-file", "bpf.o", "section", "tc")
		if out, err := cmdAttachEgress.CombinedOutput(); err != nil {
			log.Printf("Failed to attach BPF program to egress on %s: %v. Output: %s", iface.Name, err, string(out))
			// 清理 qdisc
			exec.Command("tc", "qdisc", "del", "dev", iface.Name, "clsact").Run()
			continue
		}

		log.Printf("Successfully attached TC program to egress of interface %q", iface.Name)
		attachedInterfaces = append(attachedInterfaces, iface.Name)
	}

	if len(attachedInterfaces) == 0 {
		log.Fatalf("Could not attach to any suitable network interfaces. Please ensure you are running as root or with CAP_NET_ADMIN capabilities.")
	}

	// 捕获退出信号，以便执行清理操作
	go func() {
		<-stopper
		log.Println("Received shutdown signal, cleaning up and exiting...")

		// 程序退出时，清理所有附加的 TC 规则和 qdisc
		for _, ifaceName := range attachedInterfaces {
			log.Printf("Detaching from interface %s", ifaceName)
			// 删除 qdisc 会自动删除附加在上面的所有 filter
			if err := exec.Command("tc", "qdisc", "del", "dev", ifaceName, "clsact").Run(); err != nil {
				log.Printf("Failed to delete qdisc on %s: %v", ifaceName, err)
			}
		}
		os.Exit(0)
	}()

	// 阻塞主goroutine，让程序持续运行
	select {}
}