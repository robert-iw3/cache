/*
 * ==============================================================================
 * Script Name: c2_loader.c
 * Version: 2.8
 * Description: User-space loader and mathematical processing layer.
 * Retrieves raw telemetry and payload buffers from the kernel ring
 * buffer. Performs heavy-lifting string parsing for DNS and
 * floating-point calculations for Shannon Entropy, bypassing kernel
 * eBPF limitations. Outputs uniform JSON to the Python broker.
 * ==============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <math.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>          // For XDP_FLAGS_SKB_MODE + bpf_xdp_attach
#include "c2_probe.skel.h"

struct event_t {
    uint32_t pid;
    uint32_t type;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t dport;
    uint16_t is_outbound;
    uint32_t packet_size;
    uint64_t ts;
    uint64_t interval_ns;
    char comm[16];
    uint8_t payload[64];
};

double calculate_shannon_entropy(const uint8_t *payload, int len) {
    int counts[256] = {0};
    for (int i = 0; i < len; i++) {
        counts[payload[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

void parse_dns(const uint8_t *payload, char *out) {
    int offset = 12; // Skip standard DNS header
    for (int i = 0; i < 63; i++) {
        uint8_t c = payload[offset + i];
        if (c == 0) { out[i] = '\0'; break; }
        if (c < 32 || c > 126) out[i] = '.';
        else out[i] = c;
    }
    out[63] = '\0';
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;

    struct in_addr ip_addr;
    ip_addr.s_addr = e->daddr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr, ip_str, INET_ADDRSTRLEN);

    const char *type_str = "unknown";
    double entropy = 0.0;
    char dns_query[64] = {0};

    switch (e->type) {
        case 1: type_str = "exec"; break;
        case 2: type_str = "connect"; break;
        case 3: type_str = "send"; break;
        case 4: type_str = "recv"; break;
        case 5: type_str = "memfd"; break;
        case 6:
            type_str = "dns";
            parse_dns(e->payload, dns_query);
            break;
        case 7:
            type_str = "tcp_payload";
            entropy = calculate_shannon_entropy(e->payload, 64);
            break;
    }

    // Output unified JSON format (unchanged)
    printf("{\"pid\": %u, \"comm\": \"%s\", \"type\": \"%s\", \"packet_size\": %u, \"is_outbound\": %u, \"dst_ip\": \"%s\", \"daddr\": %u, \"dst_port\": %u, \"interval_ns\": %llu, \"entropy\": %.3f, \"dns_query\": \"%s\"}\n",
           e->pid, e->comm, type_str, e->packet_size, e->is_outbound, ip_str, e->daddr, e->dport, (unsigned long long)e->interval_ns, entropy, dns_query);

    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    struct c2_probe_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    const char *iface = (argc > 1) ? argv[1] : "eth0";
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "[-] Failed to resolve interface %s. Does it exist?\n", iface);
        return 1;
    }

    skel = c2_probe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Pin blocklist map for XDP
    bpf_map__unpin(skel->maps.blocklist, "/sys/fs/bpf/c2_blocklist");
    err = bpf_map__pin(skel->maps.blocklist, "/sys/fs/bpf/c2_blocklist");
    if (err) {
        fprintf(stderr, "[-] Warning: Failed to pin XDP blocklist.\n");
    }

    // Attach kprobes + tracepoints via skeleton (execve, memfd_create, tcp/udp hooks)
    err = c2_probe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to attach BPF programs (kprobes/tracepoints)\n");
        goto cleanup;
    }

    // ==============================================================================
    // FUTURE-PROOF XDP ATTACHMENT (Generic SKB mode)
    // ==============================================================================
    printf("[XDP] Detaching any previous program on %s (prevents -EBUSY)...\n", iface);
    bpf_xdp_detach(ifindex, 0, NULL);   // Clean slate

    __u32 xdp_flags = XDP_FLAGS_SKB_MODE;   // Works on Wi-Fi, containers, VMs, all kernels

    int xdp_fd = bpf_program__fd(skel->progs.xdp_drop_malicious);
    err = bpf_xdp_attach(ifindex, xdp_fd, xdp_flags, NULL);
    if (err) {
        fprintf(stderr, "[-] Failed to attach XDP even in generic SKB mode: %d\n", err);
        goto cleanup;
    }

    printf("[XDP] SUCCESS: Attached in generic SKB mode to %s (future-proof)\n", iface);

    // Ring buffer for events
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "[-] Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("{\"status\": \"C-Loader initialized. XDP (generic SKB) + Tracepoints active on %s.\"}\n", iface);
    fflush(stdout);

    // Main event loop
    while (1) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "[-] Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    c2_probe_bpf__destroy(skel);
    return -err;
}