package main

import (
	_ "fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"

	"os/signal"
	_ "strings"

	"github.com/cilium/ebpf/rlimit"
)
// go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_tcp_option_kern.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include
func main() {
	// 订阅中断信号，用于优雅退出
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 提升 eBPF 程序的内存锁定限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// 1. 查找我们想要操作的特定网络接口'ens192'
	ifaceName := "ens192"
	_, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Lookup for network interface %s failed: %s", ifaceName, err)
	}

	// 2. 清理旧的 qdisc (如果存在)，确保环境干净
	// 这使得脚本可以被多次重复运行而不会出错
	exec.Command("tc", "qdisc", "del", "dev", ifaceName, "clsact").Run()
	log.Printf("Cleaned up existing qdisc on %s (if any)", ifaceName)

	// 3. 为接口 'ens192' 添加 clsact qdisc
	// 这是挂载 TC (Traffic Control) BPF 程序的先决条件
	cmdAddQdisc := exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact")
	if out, err := cmdAddQdisc.CombinedOutput(); err != nil {
		log.Fatalf("Failed to add qdisc to interface %s: %v\nOutput: %s", ifaceName, err, string(out))
	}
	log.Printf("Added clsact qdisc to interface %s", ifaceName)

	// defer 语句确保在程序退出时，无论何种原因，都会执行清理操作
	defer func() {
		log.Printf("Detaching TC filter and qdisc from %s", ifaceName)
		if err := exec.Command("tc", "qdisc", "del", "dev", ifaceName, "clsact").Run(); err != nil {
			log.Printf("Failed to delete qdisc on %s: %v", ifaceName, err)
		}
	}()

	// 4. 附加 eBPF 程序到 egress (出口) hook
	// 我们直接使用 bpf2go 生成的 .o 文件，bpf2go 会根据你的系统架构选择
	// 'bpf_bpfel.o' (Little Endian) 或 'bpf_bpfeb.o' (Big Endian)
	// 我们在这里直接指定 bpfel.o，因为 x86_64 是小端架构
	objFileName := "bpf_bpfel.o"

	// 'bpf2go' 在 'go generate' 期间已经将 C 代码编译成了这个 .o 文件
	// 我们的 Makefile 确保了这个 .o 文件和 Go 可执行文件都在容器的 /app 目录下
	cmdAttachEgress := exec.Command("tc", "filter", "add", "dev", ifaceName, "egress", "bpf", "direct-action", "object-file", objFileName, "section", "tc")

	// [重要] 设置命令的执行目录
	// 假设 Dockerfile 将 ebpf-injector 和 bpf_bpfel.o 都放在了 /app/ 目录
	// 如果不设置，它可能会在 / 目录下执行，从而找不到 bpf_bpfel.o
	cmdAttachEgress.Dir = "/app" // 或者是你 Dockerfile 中设置的 WORKDIR

	if out, err := cmdAttachEgress.CombinedOutput(); err != nil {
		log.Fatalf("Failed to attach BPF program to egress on %s: %v\nOutput: %s", ifaceName, err, string(out))
	}

	log.Printf("Successfully attached TC program to egress of interface %q", ifaceName)
	log.Println("eBPF injector is running. Press Ctrl-C to exit and clean up.")

	// 等待程序被终止的信号 (例如 Ctrl+C)
	<-stopper

	log.Println("Received shutdown signal, cleaning up and exiting.")
}