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

# generate 目标:
# 1. 在正确的目录下运行 go generate
# 2. (调试) 显示生成后的文件
# 3. 将生成的 .o 文件移动到项目根目录
# 4. (调试) 确认文件已被移走
generate:
	@echo "==> 1. Generating eBPF assets in cmd/main..."
	cd cmd/main && go generate ./...

	@echo "==> 2. Files in cmd/main AFTER generation:"
	ls -l cmd/main

	@echo "==> 3. Moving $(BPF_OBJECT) to root directory..."
	cp cmd/main/$(BPF_OBJECT) .

	@echo "==> 4. Files in root directory and cmd/main AFTER move:"
	ls -l
	@echo "---"
	ls -l cmd/main



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
