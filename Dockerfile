# ---- Build Stage ----
FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y clang libelf-dev libbpf-dev linux-tools-common linux-tools-generic build-essential git

WORKDIR /src
RUN git clone https://github.com/libbpf/libbpf-bootstrap.git /libbpf-bootstrap
WORKDIR /libbpf-bootstrap
RUN git submodule update --init --recursive
RUN make -C src/bpftool

COPY bpf_program.c /src/
COPY loader.c /src/

WORKDIR /src
RUN clang -O2 -g -target bpf -c bpf_program.c -o bpf_program.o \
    -I/libbpf-bootstrap/libbpf/src/

RUN /libbpf-bootstrap/src/bpftool/bpftool gen skeleton bpf_program.o > bpf_program.skel.h

RUN gcc -g -Wall loader.c -o loader \
    -I/libbpf-bootstrap/libbpf/src/ \
    -L/libbpf-bootstrap/libbpf/src/ -lbpf

# ---- Final Stage ----
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y libbpf-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /src/loader .

ENTRYPOINT ["/loader"]
