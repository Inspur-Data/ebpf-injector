package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// [最终核心修正]
// 由于 bpf_tcp_option_kern.c 和 main.go 现在位于同一个目录，go:generate 指令变得极其简单。
//
// 1. bpf:                  我们告诉 bpf2go，生成的 Go 变量和类型都以 "bpf" 作为前缀。
// 2. bpf_tcp_option_kern.c: 直接引用同目录下的 C 文件名。
// 3. -- -I...:             提供了所有正确的 clang 编译标志，一次性解决了所有头文件找不到的问题。
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_tcp_option_kern.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include

const (
	// sockops 程序需要挂载到 cgroup v2 的根目录
	cgroupPath = "/sys/fs/cgroup"
)

func main() {
	log.Println("Starting eBPF TOA injector...")

	// 订阅停止信号，用于优雅退出
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 为 eBPF 资源解除内存锁定限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock limit:", err)
	}

	// 加载预编译的 eBPF 程序和 map 到内核
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Error loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// 将 sockops 程序挂载到 cgroup
	// 这是让 sockops 程序生效的关键步骤
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.BpfSockopsToa, // 函数名来自 C 文件中的 SEC("sockops") int bpf_sockops_toa
	})
	if err != nil {
		log.Fatalf("Error attaching cgroup program: %v", err)
	}
	defer l.Close()

	log.Printf("eBPF sockops program attached successfully to cgroup %s", cgroupPath)
	log.Println("Injector is running. Press Ctrl-C to exit and detach the program.")

	// 阻塞，直到接收到退出信号
	<-stopper

	log.Println("Received shutdown signal, detaching program and exiting.")
}
