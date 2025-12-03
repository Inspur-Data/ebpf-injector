/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

/* Helper macro to place programs, maps, license in
 * different sections in elf_bpf object file.
 * Section names are used by kernel and libbpf to understand what is inside.
 *
 * To expose helper functions to user-space application, new custom section can
 * be added and it will be recognized by libbpf based on ELF section names.
 * Each in-kernel generated code bit falls into appropriate section.
 */

/* Macro to emit attribute when used with clang as the compiler, an attribute
 * for any other gcc-like compiler is __has_attribute() to check.
 */
#if __has_attribute(preserve_static_offset)
#define __BPF_PRESERVE_STATIC_OFFSET __attribute__((preserve_static_offset))
#else
#define __BPF_PRESERVE_STATIC_OFFSET
#endif

/* Helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, unsigned long long flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read)(void *dst, unsigned long sz, const void *unsafe_ptr) = (void *)4;
static unsigned long long (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_trace_printk)(const char *fmt, unsigned long fmt_size, ...) = (void *)6;
static void (*bpf_get_current_pid_tgid)(void) = (void *)14;
static unsigned long long (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, unsigned long buf_size) = (void *)16;
static unsigned long long (*bpf_get_smp_processor_id)(void) = (void *)8;
static long (*bpf_perf_event_read)(void *map, unsigned long long flags) = (void *)22;
static long (*bpf_clone_redirect)(void *skb, unsigned long long ifindex, unsigned long long flags) = (void *)13;
static long (*bpf_get_route_realm)(void *skb) = (void *)17;
static long (*bpf_perf_event_output)(void *ctx, void *map, unsigned long long flags, void *data, unsigned long long size) = (void *)25;
static long (*bpf_get_stackid)(void *ctx, void *map, unsigned long long flags) = (void *)27;
static long (*bpf_csum_diff)(void *from, unsigned long from_size, void *to, unsigned long to_size, unsigned long long seed) = (void *)28;
static long (*bpf_skb_get_tunnel_opt)(void *skb, void *opt, unsigned long size) = (void *)29;
static long (*bpf_skb_set_tunnel_opt)(void *skb, void *opt, unsigned long size) = (void *)30;
static long (*bpf_skb_change_proto)(void *skb, unsigned short proto, unsigned long flags) = (void *)31;
static long (*bpf_skb_change_type)(void *skb, unsigned long type) = (void *)32;
static unsigned long long (*bpf_skb_under_cgroup)(void *skb, void *map, unsigned long index) = (void *)33;
static long (*bpf_get_hash_recalc)(void *skb) = (void *)34;
static long (*bpf_get_current_task)(void) = (void *)35;
static long (*bpf_probe_write_user)(void *dst, const void *src, unsigned long sz) = (void *)36;
static long (*bpf_current_task_under_cgroup)(void *map, unsigned long index) = (void *)37;
static long (*bpf_skb_change_tail)(void *skb, unsigned long len, unsigned long flags) = (void *)38;
static long (*bpf_skb_pull_data)(void *skb, unsigned long len) = (void *)39;
static long long (*bpf_csum_update)(void *skb, unsigned short csum) = (void *)40;
static void (*bpf_set_hash_invalid)(void *skb) = (void *)41;
static long (*bpf_get_numa_node_id)(void) = (void *)42;
static long (*bpf_probe_read_kernel)(void *dst, unsigned long sz, const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_user)(void *dst, unsigned long sz, const void *unsafe_ptr) = (void *)112;
static long (*bpf_probe_read_kernel_str)(void *dst, unsigned long sz, const void *unsafe_ptr) = (void *)115;
static long (*bpf_probe_read_user_str)(void *dst, unsigned long sz, const void *unsafe_ptr) = (void *)114;
static long (*bpf_skb_output)(void *ctx, void *map, unsigned long long flags, void *data, unsigned long data_len) = (void *)61;
static long (*bpf_skb_load_bytes)(const void *skb, unsigned long offset, void *to, unsigned long len) = (void *)26;
static long (*bpf_skb_store_bytes)(void *skb, unsigned long offset, const void *from, unsigned long len, unsigned long flags) = (void *)9;
static long (*bpf_skb_adjust_room)(void *skb, long len_diff, unsigned long mode, unsigned long flags) = (void *)44;
static long (*bpf_redirect_map)(void *map, unsigned long key, unsigned long flags) = (void *)51;
static unsigned short (*bpf_htons)(unsigned short hostshort) = (void *)87;
static unsigned short (*bpf_ntohs)(unsigned short netshort) = (void *)88;
static unsigned int (*bpf_htonl)(unsigned int hostlong) = (void *)89;
static unsigned int (*bpf_ntohl)(unsigned int netlong) = (void *)90;

/* Memory */
#define memset(x, c, n)   __builtin_memset((x), (c), (n))
#define memcpy(x, y, n)   __builtin_memcpy((x), (y), (n))
#define memmove(x, y, n)  __builtin_memmove((x), (y), (n))

/* Logging */
#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

#endif /* __BPF_HELPERS__ */
