package main

import (
	_ "github.com/cilium/ebpf/link"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"

	"os/signal"
	_ "path/filepath"
	"strings"

	"github.com/cilium/ebpf/rlimit"
)
// go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_tcp_option_kern.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include
func main() {
	log.Println("Starting eBPF injector...")

	// 监听 Ctrl+C 等中断信号
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// eBPF 程序通常需要提升内存锁定限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// 检查 bpf2go 生成的 .o 文件是否存在
	// 这是 tc 命令将要使用的文件
	objFileName := "bpf_bpfel.o"
	if _, err := os.Stat(objFileName); os.IsNotExist(err) {
		log.Fatalf("eBPF object file %s not found. Please run 'go generate' first.", objFileName)
	}

	// 获取所有网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to get network interfaces: %v", err)
	}

	var attachedInterfaces []string

	// 遍历所有网络接口
	for _, iface := range ifaces {
		if iface.Name != "ens192"{
			continue
		}
		// 忽略 loopback、down状态的接口，以及常见的虚拟网卡（如 veth, docker0）
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(iface.Name, "veth") || strings.HasPrefix(iface.Name, "docker") {
			continue
		}

		log.Printf("Attempting to attach to interface %s...", iface.Name)

		// 1. 添加 clsact qdisc (排队规则)，这是挂载 TC BPF 程序的先决条件
		//    `tc qdisc add dev <iface> clsact`
		//    如果已经存在，它会报错，我们可以忽略这个错误
		_ = exec.Command("tc", "qdisc", "del", "dev", iface.Name, "clsact").Run() // 先尝试删除，确保一个干净的状态
		cmdAddQdisc := exec.Command("tc", "qdisc", "add", "dev", iface.Name, "clsact")
		if out, err := cmdAddQdisc.CombinedOutput(); err != nil {
			log.Printf("Failed to add qdisc to interface %s: %v. Output: %s", iface.Name, err, string(out))
			continue
		}

		// 2. 附加 BPF 程序到 egress (出口) hook
		//    命令: tc filter add dev <iface> egress bpf direct-action object-file <file.o> section <sec_name>
		cmdAttachEgress := exec.Command("tc", "filter", "add", "dev", iface.Name, "egress", "bpf", "direct-action", "object-file", objFileName, "section", "tc")
		if out, err := cmdAttachEgress.CombinedOutput(); err != nil {
			log.Printf("Failed to attach BPF program to egress on %s: %v. Output: %s", iface.Name, err, string(out))
			// 如果附加失败，清理掉刚刚创建的 qdisc
			exec.Command("tc", "qdisc", "del", "dev", iface.Name, "clsact").Run()
			continue
		}

		log.Printf("Successfully attached TC program to egress of interface %q", iface.Name)
		attachedInterfaces = append(attachedInterfaces, iface.Name)
	}

	if len(attachedInterfaces) == 0 {
		log.Fatalf("Could not attach to any suitable network interfaces. Please ensure you are running as root or with CAP_NET_ADMIN capabilities.")
	}

	// 启动一个 goroutine 来等待停止信号
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

	log.Println("eBPF injector is running. Press Ctrl-C to exit.")
	// 阻塞主goroutine，让程序持续运行
	select {}
}