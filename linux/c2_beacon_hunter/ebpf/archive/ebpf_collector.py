#!/usr/bin/env python3
"""
ebpf_collector.py - v2.7 eBPF Data Collector
Provides telemetry to baseline_learner.py for C2 detection

sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
sudo dnf install bcc python3-bcc kernel-headers-$(uname -r)
"""

import time
import threading
from datetime import datetime
from bcc import BPF
import os
import sys

try:
    from baseline_learner import BaselineLearner
except ImportError:
    print("Error: baseline_learner.py not found.")
    sys.exit(1)

class EBPFCollector:
    def __init__(self):
        self.learner = BaselineLearner()
        self.running = True
        self.bpf = None

    def load_probes(self):
        bpf_text = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>

        struct data_t {
            u32 pid;
            u32 ppid;
            u64 ts;
            char comm[16];
            u32 dst_ip;
            u16 dst_port;
            u32 type;           // 1=exec, 2=connect, 3=send, 4=recv, 5=memfd, 6=socket
            u32 packet_size;
            u32 is_outbound;
        };

        BPF_PERF_OUTPUT(events);

        // 1. Process Execution with parent PID
        int trace_exec(struct pt_regs *ctx) {
            struct data_t data = {};
            struct task_struct *task;
            data.pid = bpf_get_current_pid_tgid() >> 32;
            task = (struct task_struct *)bpf_get_current_task();
            data.ppid = task->real_parent->pid;
            data.ts = bpf_ktime_get_ns();
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            data.type = 1;
            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        // 2. Outbound Connect
        int trace_connect(struct pt_regs *ctx) {
            struct data_t data = {};
            data.pid = bpf_get_current_pid_tgid() >> 32;
            data.ts = bpf_ktime_get_ns();
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            data.type = 2;
            data.is_outbound = 1;
            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        // 3. Send (Outbound data + size)
        int trace_sendmsg(struct pt_regs *ctx) {
            struct data_t data = {};
            data.pid = bpf_get_current_pid_tgid() >> 32;
            data.ts = bpf_ktime_get_ns();
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            data.type = 3;
            data.is_outbound = 1;
            data.packet_size = PT_REGS_PARM3(ctx);
            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        // 4. Recv (Inbound data + size)
        int trace_recvmsg(struct pt_regs *ctx) {
            struct data_t data = {};
            data.pid = bpf_get_current_pid_tgid() >> 32;
            data.ts = bpf_ktime_get_ns();
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            data.type = 4;
            data.packet_size = PT_REGS_PARM3(ctx);
            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        // 5. Fileless Execution
        int trace_memfd(struct pt_regs *ctx) {
            struct data_t data = {};
            data.pid = bpf_get_current_pid_tgid() >> 32;
            data.ts = bpf_ktime_get_ns();
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            data.type = 5;
            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        // 6. Socket Creation
        int trace_socket(struct pt_regs *ctx) {
            struct data_t data = {};
            data.pid = bpf_get_current_pid_tgid() >> 32;
            data.ts = bpf_ktime_get_ns();
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            data.type = 6;
            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }
        """

        self.bpf = BPF(text=bpf_text)

        # Attach probes
        self.bpf.attach_kprobe(event="sys_execve", fn_name="trace_exec")
        self.bpf.attach_kprobe(event="sys_connect", fn_name="trace_connect")
        self.bpf.attach_kprobe(event="sys_sendmsg", fn_name="trace_sendmsg")
        self.bpf.attach_kprobe(event="sys_recvmsg", fn_name="trace_recvmsg")
        self.bpf.attach_kprobe(event="sys_memfd_create", fn_name="trace_memfd")
        self.bpf.attach_kprobe(event="sys_socket", fn_name="trace_socket")

        print(f"[{datetime.now()}] eBPF collector loaded: exec, connect, send/recv, memfd, socket, ppid")

    def process_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        process_name = event.comm.decode('utf-8', errors='ignore').strip()

        if event.type == 1:      # exec
            self.learner.record_flow(process_name, "0.0.0.0", 0, 0, 0, 0)
        elif event.type == 2:    # connect
            self.learner.record_flow(process_name, "0.0.0.0", 0, 0, 1.0, 0)
        elif event.type == 3:    # send
            self.learner.record_flow(process_name, "0.0.0.0", 0, 0, 1.0, 0, event.packet_size)
        elif event.type == 4:    # recv
            self.learner.record_flow(process_name, "0.0.0.0", 0, 0, 0.0, 0, event.packet_size)
        elif event.type == 5:    # memfd
            self.learner.record_flow(process_name, "0.0.0.0", 0, 0, 0, 0)
        elif event.type == 6:    # socket
            self.learner.record_flow(process_name, "0.0.0.0", 0, 0, 0, 0)

    def run(self):
        self.load_probes()
        self.bpf["events"].open_perf_buffer(self.process_event)

        print(f"[{datetime.now()}] eBPF collector running - feeding rich data to baseline_learner...")

        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"eBPF poll error: {e}")

    def stop(self):
        self.running = False
        print("eBPF collector stopped.")


if __name__ == "__main__":
    collector = EBPFCollector()
    try:
        collector.run()
    except KeyboardInterrupt:
        collector.stop()