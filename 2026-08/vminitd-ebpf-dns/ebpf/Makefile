# Builds the ONE eBPF object dnslink embeds: dns_sockaddr.bpf.o
# (sections cgroup/connect4 + cgroup/sendmsg4 + cgroup/recvmsg4,
# sharing one cfg_map + keyed hit_cnt).
#
# On the GitHub ubuntu-24.04-arm runner (and any Linux with the same deps):
#   sudo apt-get install -y clang libbpf-dev linux-libc-dev
#   make            # or: make BTF=1
# The SYSTEM libbpf-dev package provides bpf/bpf_helpers.h
# (clang finds /usr/include/bpf by default); kernel ABI types come from the
# vmlinux.h submodule (pinned, per-arch). Nothing is vendored in this repo.
#
# Non-Linux override: if your bpf_helpers.h lives elsewhere (e.g. macOS dev),
#   make BPF_SYSINC='-I/path/to/bpf-headers/include'
#
# NOTE: keep comments off assignment lines — GNU Make 3.81 (macOS) mishandles
# inline comments after :=; split lines are portable to 3.81 and 4.4.

CLANG ?= clang
STRIP ?= llvm-strip

# aarch64 on the Linux runner, arm64 on macOS.
MACHINE := $(shell uname -m)

# bpf_helpers.h; empty means use the compiler's
# system include dirs (clang finds /usr/include/bpf).
BPF_SYSINC ?=

ifdef BTF
    BTF_CFLAGS := -DWITH_BTF -g
    LEGACY_MAP :=
else
    BTF_CFLAGS :=
    LEGACY_MAP := bpf_map_def.h
endif
BPF_CFLAGS := $(BTF_CFLAGS) -O2 -target bpf -Wall $(BPF_SYSINC) -Ivmlinux.h/include/$(MACHINE)

VMLINUX_H := vmlinux.h/include/$(MACHINE)/vmlinux.h

dns_sockaddr.bpf.o: dns_sockaddr.bpf.c dns_cfg.h $(LEGACY_MAP) $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@printf '     built %-36s %6d bytes\n' "$@" "$$(stat -c%s "$@" 2>/dev/null || stat -f%z "$@")"
ifdef BTF
	$(STRIP) -g $@
	@printf '  stripped %-36s %6d bytes\n' "$@" "$$(stat -c%s "$@" 2>/dev/null || stat -f%z "$@")"
endif

clean:
	rm -f dns_sockaddr.bpf.o

.PHONY: clean
