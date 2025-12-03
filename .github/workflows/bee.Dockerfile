# 使用一个最小的运行时基础镜像
FROM ubuntu:22.04

# 仅安装运行时依赖
RUN apt-get update && apt-get install -y libbpf-dev && rm -rf /var/lib/apt/lists/*

# 创建工作目录
WORKDIR /

# 拷贝由bee build命令在CI步骤中生成的二进制文件
COPY loader .
COPY bpf_program.o .

# 设置入口点
ENTRYPOINT ["/loader"]
