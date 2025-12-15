# Makefile

BINARY_NAME = ebpf-injector

.PHONY: all build generate clean

all: build

# 编译 Go 应用程序
# 关键：我们不再从根目录构建，而是直接在目标目录中完成所有操作
build:
	@echo "  > Building Go binary in cmd/main..."
	cd cmd/main && go generate && go build -o ../../$(BINARY_NAME) .

# generate 目标现在只是一个占位符，实际操作已合并到 build 目标中
generate:
	@echo "  > Generation step is now part of the build step."

# 清理生成的文件
clean:
	@echo "  > Cleaning up..."
    rm -f $(BINARY_NAME) ./cmd/main/bpf_*.go ./cmd/main/bpf_*.o
