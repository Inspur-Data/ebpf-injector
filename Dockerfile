# ---- Build Stage ----
FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y clang libelf-dev libbpf-dev linux-tools-common linux-tools-generic build-essential git pkg-config

WORKDIR /tmp
RUN git clone https://github.com/libbpf/libbpf-bootstrap.git
WORKDIR /tmp/libbpf-bootstrap
RUN git submodule update --init --recursive

# Build bpftool
WORKDIR /tmp/libbpf-bootstrap/src/bpftool
RUN make

COPY bpf_program.c /src/
COPY loader.c /src/

WORKDIR /src
RUN clang -O2 -g -target bpf -c bpf_program.c -o bpf_program.o \
    -I/tmp/libbpf-bootstrap/libbpf/src/

RUN /tmp/libbpf-bootstrap/src/bpftool/bpftool gen skeleton bpf_program.o > bpf_program.skel.h

RUN gcc -g -Wall loader.c -o loader \
    -I/tmp/libbpf-bootstrap/libbpf/src/ \
    -L/tmp/libbpf-bootstrap/libbpf/src/ -lbpf

# ---- Final Stage ----
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y libbpf-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /src/loader .

ENTRYPOINT ["/loader"]
