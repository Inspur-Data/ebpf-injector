FROM ubuntu:22.04

# 仅安装运行时必须的libbpf库
RUN apt-get update && apt-get install -y libbpf-dev && rm -rf /var/lib/apt/lists/*

# 创建工作目录
WORKDIR /

# 【重要】拷贝我们在CI步骤中编译好的二进制文件
# docker/build-push-action@v4 会将整个context（包括编译产物）发送给docker build
COPY loader .
COPY bpf_program.o .

# 设置默认入口点
ENTRYPOINT ["/loader"]
