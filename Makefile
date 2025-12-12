# 默认的 C 编译器
CLANG ?= clang
# eBPF 程序的编译标志
CFLAGS ?= -O2 -g -Wall -Werror

# 最终生成的二进制文件名
BINARY_NAME = ebpf-injector
# Docker 镜像标签
DOCKER_IMAGE = registry.cn-hangzhou.aliyuncs.com/testwydimage/ebpf-injector:latest # GitHub Packages 镜像地址

.PHONY: all build generate clean

all: build

# 编译 Go 应用程序
build: generate
	@echo "  > Building Go binary..."
	# 从 cmd/injector 目录构建，并将输出放在项目根目录
	cd cmd/ringbuffer  && go build -o ../../$(BINARY_NAME) .

# 导出环境变量并运行 go generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	@echo "  > Generating eBPF Go assets..."
	go generate ./...

# 清理生成的文件
clean:
	@echo "  > Cleaning up..."
	rm -f $(BINARY_NAME) ./bpf/bpf_bpfel.go

# 构建 Docker 镜像
docker-build:
	@echo "  > Building Docker image: $(DOCKER_IMAGE)"
	docker build -t $(DOCKER_IMAGE) .

# 推送 Docker 镜像
docker-push:
	@echo "  > Pushing Docker image: $(DOCKER_IMAGE)"
	docker push $(DOCKER_IMAGE)
