# 最终生成的二进制文件名
BINARY_NAME = ebpf-injector
# Docker 镜像标签
DOCKER_IMAGE = registry.cn-hangzhou.aliyuncs.com/testwydimage/ebpf-injector:latest
# eBPF 对象文件的名称
BPF_OBJECT = bpf_bpfel.o
.PHONY: all build generate clean docker-build docker-push

all: build

# 编译 Go 应用程序
build: generate
	@echo "  > Building Go binary..."
	cd cmd/main && go build -o ../../$(BINARY_NAME) .

# generate 目标现在极其简单，直接调用 go generate ./...
generate:
    @echo "  > Generating eBPF Go assets..."
    cd cmd/main && go generate ./...
    @echo "  > Moving $(BPF_OBJECT) to root directory..."
    cd cmd/main && ll -lsr
    mv cmd/main/$(BPF_OBJECT) .
    cd cmd/main && ll -lsr

# 构建 Docker 镜像
docker-build: build
	@echo "  > Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

# 推送 Docker 镜像
docker-push: docker-build
	@echo "  > Pushing Docker image..."
	docker push $(DOCKER_IMAGE)

# 清理生成的文件
clean:
	@echo "  > Cleaning up..."
	# [修正] 路径已从 ringbuffer 改为 main
	rm -f $(BINARY_NAME) ./cmd/main/bpf_*.go
