#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <errno.h>

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

void parse_and_update_ports(struct bpf_map *map, char *ports_str) {
    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map FD\n");
        return;
    }
    char *port_token = strtok(ports_str, ",");
    while (port_token != NULL) {
        char *range_sep = strchr(port_token, '-');
        if (range_sep) {
            *range_sep = '\0';
            int start_port = atoi(port_token);
            int end_port = atoi(range_sep + 1);
            if (start_port > 0 && end_port > 0 && end_port >= start_port) {
                printf("Enabling Proxy Protocol for port range %d-%d\n", start_port, end_port);
                for (int port = start_port; port <= end_port; port++) {
                    __u16 p = (__u16)port;
                    __u8 v = 1;
                    bpf_map_update_elem(map_fd, &p, &v, BPF_ANY);
                }
            } else {
                 fprintf(stderr, "Invalid port range: %s-%s\n", port_token, range_sep + 1);
            }
        } else {
            int port = atoi(port_token);
            if (port > 0 && port < 65536) {
                __u16 p = (__u16)port;
                __u8 v = 1;
                bpf_map_update_elem(map_fd, &p, &v, BPF_ANY);
                printf("Enabled Proxy Protocol for port %d\n", port);
            } else {
                fprintf(stderr, "Invalid port: %s\n", port_token);
            }
        }
        port_token = strtok(NULL, ",");
    }
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int ifindex;
    char *iface;
    char *ports_str;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <port_list>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 2000-3000,39075\n", argv[0]);
        return 1;
    }
    iface = argv[1];
    ports_str = argv[2];

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }
    
    obj = bpf_object__open_file("bpf_program.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }
    
    map = bpf_object__find_map_by_name(obj, "ports_map");
    if (!map) {
        fprintf(stderr, "ERROR: finding map in BPF object failed\n");
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "tc_proxy_protocol");
    if (!prog) {
        fprintf(stderr, "ERROR: finding program in BPF object failed\n");
        goto cleanup;
    }

    parse_and_update_ports(map, ports_str);

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts);

    bpf_tc_hook_destroy(&hook);
    bpf_tc_hook_create(&hook);

    opts.prog_fd = bpf_program__fd(prog);
    bpf_tc_attach(&hook, &opts);

    printf("Successfully attached eBPF program to %s. Press Ctrl+C to exit.\n", iface);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        sleep(1);
    }

cleanup:
    bpf_tc_hook_destroy(&hook);
    if (obj) {
        bpf_object__close(obj);
    }
    printf("Detached eBPF program and cleaned up.\n");
    return 0;
}
