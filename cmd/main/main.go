package main

import (
	"log"
	"net"
	"os"
	"os/exec"
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
		log.Fatal("Failed to remove memlock limit: ", err)
	}

	// 加载 eBPF 程序
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	progFD := objs.InjectTcp4opt.FD()
	if progFD < 0 {
		log.Fatal("failed to get program file descriptor")
	}

	// 获取所有网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("failed to get network interfaces: %v", err)
	}

	// 遍历并附加到每个合适的接口
	for _, iface := range ifaces {
		// 忽略 loopback 和没有启动的接口
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(iface.Name, "veth") || strings.HasPrefix(i.Name, "docker") {
			continue
		}

		log.Printf("Attempting to attach to interface %s...", iface.Name)

		// 1. 添加 clsact qdisc (如果不存在)
		//    这是挂载TC BPF程序的先决条件
		//    使用 "ip link add ... type ... " 的等价命令
		cmd_add_qdisc := exec.Command("tc", "qdisc", "add", "dev", iface.Name, "clsact")
		if err := cmd_add_qdisc.Run(); err != nil {
			// 忽略 "File exists" 错误，因为它意味着 qdisc 已经存在
			if !strings.Contains(err.Error(), "File exists") {
				log.Printf("Failed to add qdisc to interface %s: %v", iface.Name, err)
				continue
			}
		}

		// 2. 附加 BPF 程序到 ingress hook
		//    tc filter add dev <iface> ingress bpf direct-action obj <obj_file> sec <section_name>
		cmd_attach_ingress := exec.Command("tc", "filter", "add", "dev", iface.Name, "ingress", "bpf", "direct-action", "object-file", "./bpf_bpfel.o", "section", "tc")
		cmd_attach_ingress.Dir = "cmd/main" // 确保在正确的目录下执行
		if out, err := cmd_attach_ingress.CombinedOutput(); err != nil {
			log.Printf("Failed to attach BPF program to ingress on %s: %v. Output: %s", iface.Name, err, string(out))
			continue
		}

		// 3. 附加 BPF 程序到 egress hook (如果需要)
		cmd_attach_egress := exec.Command("tc", "filter", "add", "dev", iface.Name, "egress", "bpf", "direct-action", "object-file", "./bpf_bpfel.o", "section", "tc")
		cmd_attach_egress.Dir = "cmd/main"
		if out, err := cmd_attach_egress.CombinedOutput(); err != nil {
			log.Printf("Failed to attach BPF program to egress on %s: %v. Output: %s", iface.Name, err, string(out))
			// 清理 ingress 规则
			exec.Command("tc", "filter", "del", "dev", iface.Name, "ingress").Run()
			continue
		}

		log.Printf("Successfully attached TC program to interface %q", iface.Name)

		// 注册清理函数
		defer func(ifaceName string) {
			log.Printf("Detaching from interface %s", ifaceName)
			// 清理 ingress 规则
			if err := exec.Command("tc", "filter", "del", "dev", ifaceName, "ingress").Run(); err != nil {
				log.Printf("Failed to delete ingress filter on %s: %v", ifaceName, err)
			}
			// 清理 egress 规则
			if err := exec.Command("tc", "filter", "del", "dev", ifaceName, "egress").Run(); err != nil {
				log.Printf("Failed to delete egress filter on %s: %v", ifaceName, err)
			}
			// 删除 qdisc
			if err := exec.Command("tc", "qdisc", "del", "dev", ifaceName, "clsact").Run(); err != nil {
				log.Printf("Failed to delete qdisc on %s: %v", ifaceName, err)
			}
		}(iface.Name)
	}

	log.Println("eBPF injector is running. Press Ctrl-C to exit.")

	// 等待程序被终止的信号
	<-stopper

	log.Println("Received shutdown signal, cleaning up and exiting.")
}
