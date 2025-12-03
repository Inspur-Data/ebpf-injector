# ---- Build Stage ----
FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y \
    clang \
    libelf-dev \
    libelf1 \
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    build-essential \
    git \
    pkg-config \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN git clone https://github.com/libbpf/libbpf-bootstrap.git
WORKDIR /tmp/libbpf-bootstrap
RUN git submodule update --init --recursive

# Build bpftool using libbpf's build system
WORKDIR /tmp/libbpf-bootstrap/libbpf/src
RUN make -j$(nproc)

COPY bpf_program.c /src/
COPY loader.c /src/

WORKDIR /src
RUN clang -O2 -g -target bpf -c bpf_program.c -o bpf_program.o \
    -I/tmp/libbpf-bootstrap/libbpf/src/

# Use bpftool from system or build it
RUN which bpftool || apt-get install -y linux-tools-generic

RUN bpftool gen skeleton bpf_program.o > bpf_program.skel.h

RUN gcc -g -Wall loader.c -o loader \
    -I/tmp/libbpf-bootstrap/libbpf/src/ \
    -lbpf

# ---- Final Stage ----
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y libbpf-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /src/loader .

ENTRYPOINT ["/loader"]
