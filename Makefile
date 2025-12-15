# Makefile

# 最终生成的二进制文件名
BINARY_NAME = ebpf-injector

.PHONY: all build generate clean

all: build

# 编译 Go 应用程序
build: generate
	@echo "  > Building Go binary..."
	# [最终核心修正]
	# 我们完全模仿模板的构建方式：
	# 1. 'cd' 进入 main.go 所在的目录。
	# 2. 在那里运行 'go build'。
	# 3. 将编译好的二进制文件输出到项目的根目录。
	cd cmd/ringbuffer && go build -o ../../$(BINARY_NAME) .

# generate 目标现在极其简单，直接调用 go generate ./...
generate:
	@echo "  > Generating eBPF Go assets..."
	go generate ./...

# 清理生成的文件
clean:
	@echo "  > Cleaning up..."
	# 删除根目录的二进制文件，以及在 cmd/ringbuffer 目录下生成的 Go 文件。
	rm -f $(BINARY_NAME) ./cmd/ringbuffer/bpf_*.go
