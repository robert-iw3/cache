// dev/probes/c2_loader.c
// c2_loader.c - User-space loader for c2_probe.bpf.c v2.7
// This program loads the c2_probe.bpf.c eBPF program into the kernel, attaches the probes, and listens for events on the ring buffer.
// It outputs captured events in JSON format to stdout, which can be easily parsed by a Python script for further processing and baseline learning.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig) {
    exiting = 1;
}

// Struct matching the memory layout of c2_probe.bpf.c
struct data_t {
    unsigned int pid;
    unsigned long long ts;
    char comm[16];
    unsigned int type;
    unsigned int packet_size;
    unsigned int is_outbound;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short dport;
    unsigned long long interval_ns;
};

// Callback triggered by the kernel every time an event hits the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct data_t *e = data;

    // Output strictly formatted JSON so Python can parse it instantly
    printf("{\"pid\": %u, \"comm\": \"%s\", \"type\": %u, \"packet_size\": %u, \"is_outbound\": %u, \"daddr\": %u, \"interval_ns\": %llu}\n",
           e->pid, e->comm, e->type, e->packet_size, e->is_outbound, e->daddr, e->interval_ns);
    fflush(stdout); // CRITICAL: Flush stdout so Python subprocess.PIPE sees it immediately
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct ring_buffer *rb = NULL;
    int map_fd, err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *probe_path = (argc > 1) ? argv[1] : "c2_probe.bpf.o";

    // 1. Open the compiled eBPF object file
    obj = bpf_object__open_file(probe_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: Failed to open %s\n", probe_path);
        return 1;
    }

    // 2. Load the object into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF object\n");
        return 1;
    }

    // 3. Attach all defined programs (kprobes, tracepoints, etc.)
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "ERROR: Failed to attach program %s\n", bpf_program__name(prog));
            continue;
        }
    }

    // 4. Set up the ring buffer memory map
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: Failed to find 'events' map\n");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ERROR: Failed to create ring buffer\n");
        return 1;
    }

    // 5. Poll the buffer infinitely until terminated
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // Clean up
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}