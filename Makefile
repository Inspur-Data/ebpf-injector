# Makefile

# 最终生成的二进制文件名
BINARY_NAME = ebpf-injector

.PHONY: all build generate clean

all: build

# 编译 Go 应用程序
build: generate
	@echo "  > Building Go binary..."
	cd cmd/ringbuffer && go build -o ../../$(BINARY_NAME) .

# generate 目标现在极其简单，直接调用 go generate 即可
generate:
	@echo "  > Generating eBPF Go assets..."
	go generate ./...

# 清理生成的文件
clean:
	@echo "  > Cleaning up..."
	rm -f $(BINARY_NAME) ./bpf/bpf_bpfel.go
