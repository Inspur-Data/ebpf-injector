# ---- Build Stage ----
FROM ubuntu:22.04 as builder

# 1. 拷贝所有源代码
WORKDIR /src
COPY . .

# 2. 【终极核心】在一个单一的RUN指令中，完成所有编译
RUN \
    # --- 步骤A: 安装所有依赖 ---
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential clang llvm libelf-dev libbpf-dev gcc-multilib make linux-headers-generic && \
    \
    # --- 步骤B: 编译并安装libbpf (可选，但能保证一致性) ---
    cd /src/libbpf/src && \
    make && \
    make install && \
    \
    # --- 步骤C: 编译eBPF程序 ---
    cd /src && \
    # 【最终修正】在clang命令中，包含一个能提供基础类型定义的头文件
    # 我们不再依赖复杂的动态查找，而是直接使用由apt安装的通用头文件
    # '<asm/types.h>' 是定义 __u64 等类型的最底层文件之一
    clang \
    -O2 -g \
    -target bpf \
    \
    # 明确包含能定义 __u64 等类型的头文件
    -include /usr/include/x86_64-linux-gnu/asm/types.h \
    \
    # 依然保留这些宏定义，它们对编译内核模块风格的代码有帮助
    -D__KERNEL__ \
    -D__TARGET_ARCH_x86 \
    \
    -c bpf_program.c -o bpf_program.o && \
    \
    # --- 步骤D: 编译用户态加载器 ---
    gcc -g -Wall loader.c -o loader -lbpf


# ---- Final Stage ----
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y libbpf-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=builder /src/loader .
COPY --from=builder /src/bpf_program.o .

ENTRYPOINT ["/loader"]
