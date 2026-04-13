# ==============================================================================
# Script Name: Makefile
# Version: 2.8
# Description: Build instructions for the eBPF telemetry stack. It handles
#              generating the kernel BTF headers (vmlinux.h), compiling the
#              CO-RE compliant eBPF C code, generating the user-space
#              skeleton header, and linking the final c2_loader executable
#              with the math (-lm) library.
# ==============================================================================

APP = c2_loader
BPF_OBJ = c2_probe.bpf.o
SKEL = c2_probe.skel.h
VMLINUX = vmlinux.h

# Compilers & Tools
CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

# Architectures
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Flags - Added -lm to LDFLAGS to support Shannon Entropy log2() functions in C-Loader
CFLAGS = -g -O2 -Wall
LDFLAGS = -lbpf -lelf -lz -lm

all: $(APP)

$(VMLINUX):
	@echo "[-] Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): c2_probe.bpf.c | $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I . -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(APP): c2_loader.c $(SKEL)
	$(CC) $(CFLAGS) -I . $< -o $@ $(LDFLAGS)

clean:
	rm -f $(APP) $(BPF_OBJ) $(SKEL) $(VMLINUX)