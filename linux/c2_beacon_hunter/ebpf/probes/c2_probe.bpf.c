/*
 * ==============================================================================
 * Script Name: c2_probe.bpf.c
 * Version: 2.8
 * Description: eBPF core telemetry and enforcement engine. Utilizes the
 * "Extract and Compute" pattern to maintain wire-speed performance.
 * Intercepts process execution, interval timings, and raw payloads.
 * Enforces active defense via XDP blackholing and bpf_send_signal
 * SIGKILL terminations based on dynamic map lookups.
 * ==============================================================================
 */

// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define PAYLOAD_SAMPLE_SIZE 64
#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ==============================================================================
// MAPS
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, u8);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} last_seen_ts SEC(".maps");

// ==============================================================================
// DATA STRUCTURE
// ==============================================================================
struct event_t {
    u32 pid;
    u32 type;
    u32 saddr;
    u32 daddr;
    u16 dport;
    u16 is_outbound;
    u32 packet_size;
    u64 ts;
    u64 interval_ns;
    char comm[16];
    u8 payload[PAYLOAD_SAMPLE_SIZE];
};

static __always_inline void calculate_interval(struct event_t *e) {
    u32 pid = e->pid;
    u64 ts = e->ts;
    u64 *last_ts = bpf_map_lookup_elem(&last_seen_ts, &pid);
    if (last_ts) {
        e->interval_ns = ts - *last_ts;
    } else {
        e->interval_ns = 0;
    }
    bpf_map_update_elem(&last_seen_ts, &pid, &ts, BPF_ANY);
}

// ==============================================================================
// XDP & ENFORCEMENT
// ==============================================================================
SEC("xdp")
int xdp_drop_malicious(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    u32 daddr = iph->daddr;
    u8 *blocked_dst = bpf_map_lookup_elem(&blocklist, &daddr);
    if (blocked_dst && *blocked_dst == 1) return XDP_DROP;

    u32 saddr = iph->saddr;
    u8 *blocked_src = bpf_map_lookup_elem(&blocklist, &saddr);
    if (blocked_src && *blocked_src == 1) return XDP_DROP;

    return XDP_PASS;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk) {
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    u8 *is_blocked = bpf_map_lookup_elem(&blocklist, &daddr);
    if (is_blocked && *is_blocked == 1) {
        bpf_send_signal(9);
    }

    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    if (e->pid < 100) { bpf_ringbuf_discard(e, 0); return 0; }

    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = 2;
    e->is_outbound = 1;
    e->packet_size = 0;

    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = daddr;
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ==============================================================================
// TELEMETRY HOOKS (TRACEPOINT VERSION - FUTURE PROOF)
// ==============================================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    if (e->pid < 100) { bpf_ringbuf_discard(e, 0); return 0; }
    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = 1;
    e->is_outbound = 0;
    e->packet_size = 0;
    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    if (e->pid < 100) { bpf_ringbuf_discard(e, 0); return 0; }
    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = 5;
    e->is_outbound = 0;
    e->packet_size = 0;
    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    if (e->pid < 100) { bpf_ringbuf_discard(e, 0); return 0; }
    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->is_outbound = 1;
    e->packet_size = size;
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    e->type = 3;
    if (size >= PAYLOAD_SAMPLE_SIZE && (e->dport == 80 || e->dport == 443 || e->dport == 8080 || e->dport == 8443)) {
        e->type = 7;
        struct iovec iov = {};
        const void *iov_ptr = BPF_CORE_READ(msg, msg_iter.__iov);
        if (iov_ptr && bpf_probe_read_kernel(&iov, sizeof(iov), iov_ptr) == 0) {
            bpf_probe_read_user(&e->payload, sizeof(e->payload), iov.iov_base);
        }
    }
    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(trace_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    if (e->pid < 100) { bpf_ringbuf_discard(e, 0); return 0; }
    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = 4;
    e->is_outbound = 0;
    e->packet_size = len;
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    if (e->pid < 100) { bpf_ringbuf_discard(e, 0); return 0; }
    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->is_outbound = 1;
    e->packet_size = len;
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (e->daddr == 0) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        if (msg_name) {
            struct sockaddr_in addr = {};
            if (bpf_probe_read_user(&addr, sizeof(addr), msg_name) == 0) {
                e->daddr = addr.sin_addr.s_addr;
                e->dport = bpf_ntohs(addr.sin_port);
            }
        }
    }

    e->type = 3;
    if (e->dport == 53) {
        e->type = 6;
        struct iovec iov = {};
        const void *iov_ptr = BPF_CORE_READ(msg, msg_iter.__iov);
        if (iov_ptr && bpf_probe_read_kernel(&iov, sizeof(iov), iov_ptr) == 0) {
            bpf_probe_read_user(&e->payload, sizeof(e->payload), iov.iov_base);
        }
    }
    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    if (e->pid < 100) { bpf_ringbuf_discard(e, 0); return 0; }
    e->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->type = 4;
    e->is_outbound = 0;
    e->packet_size = len;
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    calculate_interval(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}