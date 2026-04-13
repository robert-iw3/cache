# Makefile for eBPF CO-RE C2 Probe & Loader v2.7

CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# eBPF Probe Flags
CFLAGS_BPF := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# C Loader Flags
CFLAGS_LOADER := -g -O2 -Wall
LDFLAGS_LOADER := -lbpf -lelf -lz

# Standard libbpf include paths
INCLUDES := -I/usr/include/bpf -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean

all: vmlinux.h c2_probe.bpf.o c2_loader

vmlinux.h:
	@echo "Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

c2_probe.bpf.o: c2_probe.bpf.c vmlinux.h
	@echo "Compiling eBPF probe for v2.7..."
	$(CLANG) $(CFLAGS_BPF) $(INCLUDES) -c c2_probe.bpf.c -o c2_probe.bpf.o

c2_loader: c2_loader.c
	@echo "Compiling C userspace loader..."
	$(CC) $(CFLAGS_LOADER) $(INCLUDES) c2_loader.c -o c2_loader $(LDFLAGS_LOADER)

clean:
	@echo "Cleaning up build artifacts..."
	rm -f c2_probe.bpf.o vmlinux.h c2_loader