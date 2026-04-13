/*
 * ==============================================================================
 * c2_promisc_loader.c — v3.0 (Ringbuf consumer + JSON output)
 * Author: Robert Weber
 * ==============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "c2_promisc.skel.h"

static struct c2_promisc_bpf *skel = NULL;
static volatile int exiting = 0;

struct flow_key {
    __u8  saddr[16];
    __u8  daddr[16];
    __u16 sport;
    __u16 dport;
    __u8  proto;
} __attribute__((packed));

struct aggregated_event {
    __u64 ts;
    struct flow_key key;
    __u32 pkt_count;
    __u32 total_bytes;
    __u32 payload_hash;
    __u64 avg_interval_ns;
    __u32 cv;
} __attribute__((packed));

static void sig_handler(int sig) {
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct aggregated_event *e = data;
    char dst_ip[INET6_ADDRSTRLEN] = "0.0.0.0";

    // Convert daddr (16-byte IPv4/IPv6) to string
    if (e->key.daddr[0] == 0 && e->key.daddr[1] == 0 && e->key.daddr[2] == 0 && e->key.daddr[3] == 0 &&
        e->key.daddr[4] == 0 && e->key.daddr[5] == 0 && e->key.daddr[6] == 0 && e->key.daddr[7] == 0 &&
        e->key.daddr[8] == 0 && e->key.daddr[9] == 0 && e->key.daddr[10] == 0xff && e->key.daddr[11] == 0xff) {
        // IPv4-mapped
        struct in_addr addr = { .s_addr = *(uint32_t*)(e->key.daddr + 12) };
        inet_ntop(AF_INET, &addr, dst_ip, sizeof(dst_ip));
    } else {
        inet_ntop(AF_INET6, e->key.daddr, dst_ip, sizeof(dst_ip));
    }

    // Emit SAME JSON format as legacy loader so Python side works unchanged
    printf("{\"packet_size\": %u, \"dst_ip\": \"%s\", \"dport\": %u, \"interval_ns\": %llu, "
           "\"entropy\": 0.000, \"dns_query\": \"\"}\n",
           e->total_bytes, dst_ip, e->key.dport,
           (unsigned long long)e->avg_interval_ns);

    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *iface = argc > 1 ? argv[1] : "wlo1";
    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    printf("[PROMISC-LOADER v3.0] Starting on %s (IPv4+IPv6)\n", iface);

    skel = c2_promisc_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[ERROR] Failed to open/load skeleton\n");
        return 1;
    }

    bpf_xdp_detach(ifindex, 0, NULL);

    int fd = bpf_program__fd(skel->progs.xdp_c2_promisc);
    if (bpf_xdp_attach(ifindex, fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "[ERROR] Failed to attach XDP (SKB mode)\n");
        goto cleanup;
    }

    printf("[SUCCESS] Promiscuous parser attached\n");
    printf("[READY] Ringbuf events now flowing to Python (BeaconML + hunter)\n");

    struct perf_buffer *pb = perf_buffer__new(
        bpf_map__fd(skel->maps.rb), 64, handle_event, NULL, NULL, NULL);  // 64 pages

    if (!pb) {
        fprintf(stderr, "[ERROR] Failed to create perf buffer\n");
        goto cleanup;
    }

    while (!exiting) {
        int err = perf_buffer__poll(pb, 100);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "[ERROR] Perfbuf poll error: %d\n", err);
            break;
        }
    }

    perf_buffer__free(pb);

cleanup:
    printf("[SHUTDOWN] Detaching XDP...\n");
    bpf_xdp_detach(ifindex, 0, NULL);
    c2_promisc_bpf__destroy(skel);
    return 0;
}