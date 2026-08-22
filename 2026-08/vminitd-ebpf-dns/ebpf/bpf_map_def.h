/* bpf_map_def.h — the pre-libbpf-1.0 BPF map ABI used by every object.

 * The legacy 20-byte on-disk map layout: each object embeds its maps in a
 * ".maps" section of this exact shape. The loader reads the layout straight
 * out of the compiled ELF, so the layout is part of the on-disk ABI and must
 * not change (type, key_size, value_size, max_entries, map_flags).
 *
 * INCLUDE ORDER: this header does NOT include <vmlinux.h>, so a program can
 * pick the kernel ABI version it wants. Include it (and/or dns_cfg.h) AFTER
 * <vmlinux.h> (provides __u32/__u16/__u64 kernel ABI types) and
 * <bpf/bpf_helpers.h> (provides SEC() and the map helpers). */
#ifndef BPF_MAP_DEF_H
#define BPF_MAP_DEF_H

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

#endif /* BPF_MAP_DEF_H */