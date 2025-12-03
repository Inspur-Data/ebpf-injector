# eBPF Proxy Protocol Injector - AI Coding Agent Instructions

## Project Overview
This project implements an eBPF-based network packet injector that intercepts TCP SYN packets on specified ports and prepends HAProxy's PROXY Protocol v2 headers. The solution consists of two components:
- **bpf_program.c**: eBPF kernel-space program (traffic control hook)
- **loader.c**: User-space loader that attaches the eBPF program and configures ports

## Architecture & Data Flow

### Packet Processing Pipeline
1. **Ingress TC Hook**: Traffic control (TC) classifer hook at `BPF_TC_INGRESS` intercepts all incoming packets
2. **Protocol Parsing**: Validates Ethernet → IP (IPv4 only) → TCP headers in one pass with boundary checks
3. **Port Filtering**: Looks up destination port in `ports_map` to determine if packet should be modified
4. **SYN Detection**: Only processes initial SYN packets (`tcph->syn && !tcph->ack`) to avoid redundant injection
5. **Header Injection**: Prepends 28-byte PROXY v2 header containing original source/dest IP:port

### Critical Kernel-Space Patterns (bpf_program.c)
- **Boundary Validation**: Every pointer dereference must check `(void *)ptr + size > data_end` before access - this is non-negotiable for verifier compliance
- **Map Access**: Uses `BPF_MAP_TYPE_HASH` (`ports_map`) with `__u16` key (port) and `__u8` value (1=enabled)
- **Packet Surgery**: Two operations on skb:
  - `bpf_skb_adjust_room()`: Allocates space for PROXY v2 header at packet start
  - `bpf_skb_store_bytes()`: Writes 28-byte header at offset `ETH_HLEN + iph->ihl*4 + tcph->doff*4`
- **Return Codes**: `TC_ACT_OK` (forward), `TC_ACT_SHOT` (drop), `TC_ACT_REDIRECT` (other interfaces)

### User-Space Patterns (loader.c)
- **Port Parsing**: Supports three formats: single port (`8080`), ranges (`2000-3000`), comma-separated lists (`80,443,2000-3000`)
- **Skeleton API**: Uses `bpf_program_bpf__*` functions (generated from `bpftool gen skeleton`) to manage BPF objects
- **TC Attachment**: Creates hook with `bpf_tc_hook_create()` at ingress point, cleans up with `bpf_tc_hook_destroy()` on exit
- **Signal Handling**: Graceful shutdown via `SIGINT`/`SIGTERM` to ensure proper BPF program detachment

## Build & Deployment

### Build Process (Dockerfile)
```
libbpf-bootstrap (git submodule) → clang -target bpf → bpftool gen skeleton → gcc link with libbpf
```
Key files generated during build:
- `bpf_program.o`: Compiled BPF bytecode
- `bpf_program.skel.h`: Auto-generated header (defines `bpf_program_bpf` struct)
- `loader`: User-space executable

### Runtime Requirements
- Linux kernel ≥ 5.8 (for traffic control hooks)
- `libbpf` library loaded
- Root/CAP_BPF privileges
- Interface must exist at runtime

## Common Development Tasks

### Adding a New BPF Hook Type
1. Define new program in `bpf_program.c` with `SEC("hook_type")` 
2. Recompile: `clang -target bpf -c bpf_program.c`
3. Regenerate skeleton: `bpftool gen skeleton bpf_program.o > bpf_program.skel.h`
4. Update `loader.c` to attach new program via `bpf_program__fd(skel->progs.new_program_name)`

### Debugging eBPF Programs
- Enable kernel tracing: `sudo cat /sys/kernel/debug/tracing/trace_pipe | grep bpf_printk`
- Check attachment: `sudo tc filter show dev <iface> ingress`
- Verify map contents: Use `bpftool map dump id <map_id>`

### Modifying Packet Header Structure
- **PROXY v2 Header Layout**: 12-byte signature + 1-byte version/cmd + 1-byte family + 2-byte length + payload (IPv4: 12 bytes)
- **Signature**: `\r\n\r\n\0\r\nQUIT\n` (binary magic constant)
- **Family Field**: `0x11` = AF_INET + SOCK_STREAM (IPv4/TCP)
- **Port Byte Order**: Use `bpf_htons()` for multi-byte conversions (BPF verifier requirement)

## Conventions & Gotchas
- **No Division in BPF**: Avoid `/` operator; use bit shifts or lookup tables
- **Stack Size Limit**: BPF stack is ~512 bytes; keep local variables minimal
- **Map Size**: `ports_map.max_entries = 256` - increase if monitoring >256 ports
- **Lock Safety**: BPF programs run without locks; concurrent map updates are safe (atomic on x86)
- **Packet Offset Math**: Always account for variable header sizes (`iph->ihl*4` for IP options, `tcph->doff*4` for TCP options)

## Testing & Validation
- Use tcpdump to capture modified packets: `sudo tcpdump -i <iface> -X 'tcp[tcpflags] & tcp-syn != 0'`
- Verify PROXY v2 header presence in captured packets
- Test port range parsing with edge cases: single port, overlapping ranges, invalid ports
- Ensure detachment cleans up TC hooks (verify with `sudo tc filter show dev <iface> ingress`)
