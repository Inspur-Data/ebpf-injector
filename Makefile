# Makefile

# 最终生成的二进制文件名
BINARY_NAME = ebpf-injector

.PHONY: all build generate clean

all: build

# 编译 Go 应用程序
build: generate
	@echo "  > Building Go binary..."
	# [最终核心修正]
	# 我们不再 'cd' 进入子目录。
	# 我们在项目根目录执行 go build，并明确告诉它:
	# 1. 将输出文件 (-o) 命名为 ebpf-injector 并放在当前根目录。
	# 2. 去编译位于 ./cmd/ringbuffer 的那个包。
	# 这是 Go 语言项目构建的标准、健壮的方式。
	go build -o $(BINARY_NAME) ./cmd/ringbuffer

# generate 目标现在极其简单，直接调用 go generate 即可
generate:
	@echo "  > Generating eBPF Go assets..."
	go generate ./...

# 清理生成的文件
clean:
	@echo "  > Cleaning up..."
	rm -f $(BINARY_NAME) ./bpf/bpf_bpfel.go ./bpf/bpf_bpfeb.go
