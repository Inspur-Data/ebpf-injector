# ---- Build Stage ----
FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y \
    clang \
    libelf-dev \
    libelf1 \
    libbpf-dev \
    linux-tools-generic \
    build-essential \
    git \
    pkg-config \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone and prepare libbpf-bootstrap
WORKDIR /tmp
RUN git clone https://github.com/libbpf/libbpf-bootstrap.git
WORKDIR /tmp/libbpf-bootstrap
RUN git submodule update --init --recursive

# Build libbpf library
WORKDIR /tmp/libbpf-bootstrap/libbpf/src
RUN make -j$(nproc)

# Copy source files first
COPY bpf_program.c /src/bpf_program.c
COPY loader.c /src/loader.c

# Compile eBPF program
WORKDIR /src
RUN clang -O2 -g -target bpf -c bpf_program.c -o bpf_program.o \
    -I/tmp/libbpf-bootstrap/libbpf/src/

# Generate skeleton header
RUN bpftool gen skeleton bpf_program.o > bpf_program.skel.h

# Compile user-space loader
RUN gcc -g -Wall loader.c -o loader \
    -I/tmp/libbpf-bootstrap/libbpf/src/ \
    -L/tmp/libbpf-bootstrap/libbpf/src/ \
    -lbpf

# ---- Final Stage ----
FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y libbpf0 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /src/loader .

ENTRYPOINT ["/loader"]
