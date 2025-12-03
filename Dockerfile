# ---- Build Stage ----
# 直接使用我们上面定义的、包含了所有工具的builder镜像
# 您可以先构建它，并推送到您的GHCR或Docker Hub
# 为了方便，我们也可以直接在CI中构建它
FROM ubuntu:22.04 as builder

# 1. 安装编译依赖 (与builder.Dockerfile内容一致)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential clang llvm libelf-dev libbpf-dev gcc-multilib git make

# 2. 克隆libbpf源码
WORKDIR /build
RUN git clone --depth 1 --branch v1.2.0 https://github.com/libbpf/libbpf.git
WORKDIR /build/libbpf/src
RUN make && make install

# 3. 拷贝源代码
WORKDIR /src
COPY bpf_program.c .
COPY loader.c .

# 4. 编译eBPF程序
# 使用我们从源码编译的libbpf提供的头文件
# 这是最关键的一步，保证了头文件的一致性和完整性
RUN clang \
    -I/usr/include/bpf \
    -I/usr/include/x86_64-linux-gnu \
    -O2 -g -target bpf \
    -c bpf_program.c \
    -o bpf_program.o

# 5. 编译用户态加载器
RUN gcc -g -Wall loader.c -o loader -lbpf

# ---- Final Stage ----
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y libbpf-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /src/loader .
COPY --from=builder /src/bpf_program.o .

ENTRYPOINT ["/loader"]

