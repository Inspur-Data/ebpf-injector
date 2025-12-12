# 使用一个标准的 Linux 发行版作为基础镜像
FROM ubuntu:22.04

# 设置工作目录
WORKDIR /app/

# 从构建上下文的根目录拷贝编译好的二进制文件
COPY ./ebpf-injector /app/ebpf-injector

# 安装 eBPF 程序运行所必需的 libelf1 库
RUN apt-get update \
    && apt-get install -y --no-install-recommends libelf1 \
    && rm -rf /var/lib/apt/lists/*

# 设置容器的入口点
ENTRYPOINT ["/app/ebpf-injector"]
