# ---- Build Stage ----
FROM ubuntu:22.04 as builder

# 1. 仅安装最核心的编译依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    gcc-multilib

# 2. 拷贝源代码
WORKDIR /src
COPY bpf_program.c .
COPY loader.c .

# 3. 编译eBPF程序，并捕获详细错误日志
# 如果编译失败，Action会中止，并打印出clang_error.log的内容
RUN (clang -O2 -g -target bpf -c bpf_program.c -o bpf_program.o 2>&1 | tee clang_error.log; if [ ${PIPESTATUS[0]} -ne 0 ]; then cat clang_error.log; exit 1; fi)

# 4. 编译用户态加载器
RUN gcc -g -Wall loader.c -o loader -lbpf


# ---- Final Stage ----
FROM ubuntu:22.04

# 仅安装运行时必须的libbpf库
RUN apt-get update && apt-get install -y libbpf-dev && rm -rf /var/lib/apt/lists/*

# 从构建阶段拷贝最终的可执行文件和eBPF字节码
WORKDIR /
COPY --from=builder /src/loader .
COPY --from=builder /src/bpf_program.o .

# 设置默认入口点
ENTRYPOINT ["/loader"]
