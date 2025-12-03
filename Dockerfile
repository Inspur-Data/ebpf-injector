# ---- Build Stage ----
FROM ubuntu:22.04 as builder

# 1. 安装编译依赖 (不再需要git)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential clang llvm libelf-dev libbpf-dev gcc-multilib make

# 2. 拷贝所有源代码 (包括我们通过CI下载的libbpf)
WORKDIR /src
COPY . .

# 3. 编译并安装libbpf (从本地拷贝的源码)
WORKDIR /src/libbpf/src
RUN make && make install

# 4. 编译我们的eBPF程序
WORKDIR /src
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
