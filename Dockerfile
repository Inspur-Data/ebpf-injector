# ---- Build Stage ----
FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    libelf1 \
    libbpf-dev \
    linux-headers-generic \
    linux-tools-generic \
    build-essential \
    git \
    pkg-config \
    libzstd-dev && \
    rm -rf /var/lib/apt/lists/*

# Clone libbpf-bootstrap
WORKDIR /tmp
RUN git clone --depth 1 https://github.com/libbpf/libbpf-bootstrap.git
WORKDIR /tmp/libbpf-bootstrap
RUN git submodule update --init --recursive

# Copy source files to build directory
COPY bpf_program.c /tmp/libbpf-bootstrap/src/
COPY bpf_helpers.h /tmp/libbpf-bootstrap/src/
COPY loader.c /tmp/libbpf-bootstrap/src/

# 生成 vmlinux.h（必须有 bpftool）
RUN ln -sf /usr/sbin/bpftool /usr/bin/bpftool
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h

WORKDIR /tmp/libbpf-bootstrap/src

# Compile eBPF program directly with all needed headers
RUN clang -O2 -g -target bpf \
    -I/tmp/libbpf-bootstrap/libbpf/src/uapi \
    -I/tmp/libbpf-bootstrap/libbpf/src \
    -I/tmp/libbpf-bootstrap/src \
    -c bpf_program.c -o bpf_program.o && \
    bpftool gen skeleton bpf_program.o > bpf_program.skel.h

# Build libbpf library
WORKDIR /tmp/libbpf-bootstrap/libbpf/src
RUN make -j$(nproc)

# Compile user-space loader
WORKDIR /tmp/libbpf-bootstrap/src
RUN gcc -g -Wall \
    -I/tmp/libbpf-bootstrap/libbpf/src \
    -I/tmp/libbpf-bootstrap/libbpf/src/uapi \
    loader.c -o loader \
    -L/tmp/libbpf-bootstrap/libbpf/src -lbpf -lelf -lz

# ---- Final Stage ----
FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y libbpf0 libelf1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /tmp/libbpf-bootstrap/src/loader .

ENTRYPOINT ["/loader"]

