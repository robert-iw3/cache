// c2_probe.bpf.c - CO-RE probe for v2.7
// This eBPF program is designed to monitor process execution, network connections,
// and memory file descriptor creation on Linux systems. It uses CO-RE
// (Compile Once - Run Everywhere) features to ensure compatibility across different
// kernel versions without requiring recompilation. The program captures relevant data
// such as process ID, command name, event type, packet size, and network addresses,
// and submits this information to a ring buffer for user-space processing.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[16];
    u32 type;           // 1=exec, 2=connect, 3=send, 4=recv, 5=memfd
    u32 packet_size;
    u32 is_outbound;
    u32 saddr;          // Source IPv4 address
    u32 daddr;          // Destination IPv4 address
    u16 dport;          // Destination Port
    u64 interval_ns;    // Time since last network event for this PID
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Hash map to track connection intervals
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // PID
    __type(value, u64); // Last seen timestamp
} last_seen_ts SEC(".maps");

static __always_inline void calculate_interval(struct data_t *data) {
    u32 pid = data->pid;
    u64 ts = data->ts;

    u64 *last_ts = bpf_map_lookup_elem(&last_seen_ts, &pid);
    if (last_ts) {
        data->interval_ns = ts - *last_ts;
    } else {
        data->interval_ns = 0;
    }

    bpf_map_update_elem(&last_seen_ts, &pid, &ts, BPF_ANY);
}

SEC("kprobe/sys_execve")
int BPF_KPROBE(trace_execve, const char *filename) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    if (data->pid < 100) { bpf_ringbuf_discard(data, 0); return 0; }

    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 1;
    data->is_outbound = 0;
    data->packet_size = 0;

    calculate_interval(data);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    if (data->pid < 100) { bpf_ringbuf_discard(data, 0); return 0; }

    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 2;
    data->is_outbound = 1;
    data->packet_size = 0;

    bpf_probe_read_kernel(&data->saddr, sizeof(data->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data->daddr, sizeof(data->daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&data->dport, sizeof(data->dport), &sk->__sk_common.skc_dport);

    calculate_interval(data);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    if (data->pid < 100) { bpf_ringbuf_discard(data, 0); return 0; }

    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 3;
    data->is_outbound = 1;
    data->packet_size = size;

    bpf_probe_read_kernel(&data->saddr, sizeof(data->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data->daddr, sizeof(data->daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&data->dport, sizeof(data->dport), &sk->__sk_common.skc_dport);

    calculate_interval(data);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    if (data->pid < 100) { bpf_ringbuf_discard(data, 0); return 0; }

    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 3;
    data->is_outbound = 1;
    data->packet_size = len;

    bpf_probe_read_kernel(&data->daddr, sizeof(data->daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&data->dport, sizeof(data->dport), &sk->__sk_common.skc_dport);

    // CRITICAL FIX: If UDP socket is unconnected, extract IP from the user-space msghdr struct
    if (data->daddr == 0) {
        void *msg_name;
        bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
        if (msg_name) {
            struct sockaddr_in addr;
            bpf_probe_read_user(&addr, sizeof(addr), msg_name);
            data->daddr = addr.sin_addr.s_addr;
            data->dport = addr.sin_port;
        }
    }
    calculate_interval(data);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(trace_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    if (data->pid < 100) { bpf_ringbuf_discard(data, 0); return 0; }

    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 4;
    data->is_outbound = 0;
    data->packet_size = len;

    bpf_probe_read_kernel(&data->saddr, sizeof(data->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data->daddr, sizeof(data->daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&data->dport, sizeof(data->dport), &sk->__sk_common.skc_dport);

    calculate_interval(data);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    if (data->pid < 100) { bpf_ringbuf_discard(data, 0); return 0; }

    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 4;
    data->is_outbound = 0;
    data->packet_size = len;

    bpf_probe_read_kernel(&data->daddr, sizeof(data->daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&data->dport, sizeof(data->dport), &sk->__sk_common.skc_dport);

    calculate_interval(data);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/memfd_create")
int BPF_KPROBE(trace_memfd_create) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) return 0;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    if (data->pid < 100) { bpf_ringbuf_discard(data, 0); return 0; }

    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = 5;
    data->is_outbound = 0;
    data->packet_size = 0;

    calculate_interval(data);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";