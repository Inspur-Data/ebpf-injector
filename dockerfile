# 使用一个标准的 Linux 发行版作为基础镜像
FROM ubuntu:22.04

# 安装 eBPF 运行所需的库，特别是 iproute2，它包含 'tc' 命令
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    libelf1 \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 从构建上下文中只复制编译好的Go应用程序二进制文件
COPY ebpf-injector /app/ebpf-injector
COPY cmd/main/bpf_bpfel.o /app/bpf_bpfel.o
# 设置容器的启动命令
ENTRYPOINT ["/app/ebpf-injector"]
