# ==============================================================================
# v3.0/Makefile - Builds BOTH legacy host probe AND promiscuous parser
# Usage:
#   make                  # builds both c2_loader and c2_promisc_loader
#   make host             # builds only legacy host loader
#   make promisc          # builds only promiscuous loader
#   make clean
# ==============================================================================

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# ==============================================================================
# Common build flags
# ==============================================================================
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.

# ==============================================================================
# Legacy Host-Mode Probe (original v2.8.2)
# ==============================================================================
c2_probe.bpf.o: c2_probe.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

c2_loader.skel.h: c2_probe.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

c2_loader: c2_loader.c c2_loader.skel.h
	$(CC) -g -O2 -Wall c2_loader.c -lbpf -o $@

# ==============================================================================
# Promiscuous Parser
# ==============================================================================
c2_promisc.bpf.o: c2_promisc.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

c2_promisc.skel.h: c2_promisc.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

c2_promisc_loader: c2_promisc_loader.c c2_promisc.skel.h
	$(CC) -g -O2 -Wall c2_promisc_loader.c -lbpf -o $@

# ==============================================================================
# Targets
# ==============================================================================
all: c2_loader c2_promisc_loader
	@echo "Both loaders built successfully:"
	@echo "   ./c2_loader           (legacy host mode)"
	@echo "   ./c2_promisc_loader   (promiscuous mode - Epic 1+2)"

host: c2_loader
	@echo "Legacy host loader built: ./c2_loader"

promisc: c2_promisc_loader
	@echo "Promiscuous loader built: ./c2_promisc_loader"

clean:
	rm -f *.o *.skel.h c2_loader c2_promisc_loader
	@echo "Clean complete."

.PHONY: all host promisc clean