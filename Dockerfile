# ---- Build Stage ----
# 使用一个标准的Ubuntu镜像作为构建环境
FROM ubuntu:22.04 as builder

# 1. 安装所有必需的编译依赖
# - clang, llvm, libelf-dev, libbpf-dev: eBPF编译的核心工具
# - linux-headers-generic: 提供通用的内核头文件，这是本次修改成功的关键！
# - build-essential, git, make: 标准的构建工具
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    git \
    make \
    linux-headers-generic

# 2. 拷贝源代码
WORKDIR /src
COPY bpf_program.c .
COPY loader.c .

# 3. 编译eBPF程序 (.o文件)
# 这是一个最经典、最基础的clang命令，不依赖任何动态生成的头文件
RUN clang -O2 -g -target bpf -c bpf_program.c -o bpf_program.o

# 4. 编译用户态加载器
RUN gcc -g -Wall loader.c -o loader -lbpf


# ---- Final Stage ----
# 创建一个最小的运行时镜像
FROM ubuntu:22.04

# 仅安装运行时必须的libbpf库
RUN apt-get update && apt-get install -y libbpf-dev && rm -rf /var/lib/apt/lists/*

# 从构建阶段拷贝最终的可执行文件和eBPF字节码
WORKDIR /
COPY --from=builder /src/loader .
COPY --from=builder /src/bpf_program.o . 

# 设置默认入口点
ENTRYPOINT ["/loader"]
