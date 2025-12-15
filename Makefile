# Makefile
BINARY_NAME = ebpf-injector
DOCKER_IMAGE = registry.cn-hangzhou.aliyuncs.com/testwydimage/ebpf-injector:latest

.PHONY: all build generate clean

all: build

# 编译 Go 应用程序
build: generate
	@echo "  > Building Go binary..."
	# 切换到 main 目录进行构建，然后将输出放到项目根目录
	cd cmd/main && go build -o ../../$(BINARY_NAME) .

# generate 目标现在极其简单，直接调用 go generate ./...
generate:
	@echo "  > Generating eBPF Go assets..."
	go generate ./...

# 清理生成的文件
clean:
	@echo "  > Cleaning up..."
	# 删除二进制文件和在 cmd/main 目录下生成的 go 文件
	rm -f $(BINARY_NAME) ./cmd/main/bpf_*.go ./cmd/main/bpf_*.o

# 构建 Docker 镜像
docker-build: build
	@echo "  > Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

# 推送 Docker 镜像
docker-push: docker-build
	@echo "  > Pushing Docker image..."
	docker push $(DOCKER_IMAGE)
