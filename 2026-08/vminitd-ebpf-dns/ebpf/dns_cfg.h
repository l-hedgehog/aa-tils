/* dns_cfg.h — shared DNS-redirect rule set for the socket-layer object and
 * the standalone XDP answer object.
 *
 * A single struct dns_rule describes one whole redirect; the direction is a
 * match_rule() argument, so one rule serves both query and answer hooks.
 *
 * INCLUDE ORDER: like bpf_map_def.h, this header intentionally does NOT
 * include <vmlinux.h>. Include it AFTER <vmlinux.h> (kernel ABI types,
 * BPF_MAP_TYPE_*) and <bpf/bpf_helpers.h> (SEC(), bpf_map_lookup_elem).
 */
#ifndef DNS_CFG_H
#define DNS_CFG_H

#include "bpf_map_def.h"

/* Whose eyes see a rule. A rule is one DNS redirect stated in both
 * directions; each hook only reads the half it can act on.
 *
 *   requested_* = the nameserver the resolver believes it queried.
 *   actual_*    = where the query is really sent to / answered from. */
enum dns_dir {
    DNS_QUERY  = 0,  /* connect4 / udp4_sendmsg hooks: egress, before send   */
    DNS_ANSWER = 1,  /* udp4_recvmsg / xdp hooks: ingress, answer arrives    */
};

/* One redirect rule. Field order keeps the two __u32 IPs first so the struct
 * stays exactly 12 bytes (<IIHH) — that order is part of the on-disk ABI. */
struct dns_rule {
    __u32 requested_ip;   /* matched by DNS_QUERY hooks, written by ANSWER  */
    __u32 actual_ip;      /* written by DNS_QUERY hooks, matched by ANSWER  */
    __u16 requested_port; /* matched by DNS_QUERY hooks, written by ANSWER  */
    __u16 actual_port;    /* written by DNS_QUERY hooks, matched by ANSWER  */
};

#define NUM_RULES 2

/* Index-addressable rule table; one shared instance serves every hook
 * section of the object. */
struct bpf_map_def cfg_map SEC(".maps") = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct dns_rule),
    .max_entries = NUM_RULES,
};

/* Hit-counter keys for the shared keyed hit_cnt (PERCPU_ARRAY: each CPU
 * accumulates into its own slot; the loader sums the slots per key).
 *   max_entries = 4 covers all keys: the sockaddr object uses 0/1/2;
 *   a standalone object (e.g. xdp) uses key DNS_HIT_XDP on its own map. */
enum dns_hit_key {
    DNS_HIT_CONNECT4 = 0,  /* BPF_CGROUP_INET4_CONNECT (attach 10) */
    DNS_HIT_SENDMSG  = 1,  /* BPF_CGROUP_UDP4_SENDMSG  (attach 14) */
    DNS_HIT_RECVMSG  = 2,  /* BPF_CGROUP_UDP4_RECVMSG  (attach 19) */
    DNS_HIT_XDP      = 3,  /* standalone XDP object: sole key on its private map */
};

struct bpf_map_def hit_cnt SEC(".maps") = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,  /* keys 0..3: sockaddr object uses 0/1/2; xdp uses 3 on its own private instance */
};

/* Find the rule whose (ip, port) side is the one the given direction sees.
 * Straight-line (no loop): this kernel's verifier rejects bounded loops and
 * clang's BPF target won't fully unroll one behind a helper call. */
static struct dns_rule *match_rule(__u32 ip4, __u16 port, enum dns_dir dir)
{
    __u32 key0 = 0, key1 = 1;
    struct dns_rule *r;

    r = bpf_map_lookup_elem(&cfg_map, &key0);
    if (r) {
        if (dir == DNS_QUERY &&
                ip4 == r->requested_ip && port == r->requested_port)
            return r;
        if (dir == DNS_ANSWER &&
                ip4 == r->actual_ip && port == r->actual_port)
            return r;
    }

    r = bpf_map_lookup_elem(&cfg_map, &key1);
    if (r) {
        if (dir == DNS_QUERY &&
                ip4 == r->requested_ip && port == r->requested_port)
            return r;
        if (dir == DNS_ANSWER &&
                ip4 == r->actual_ip && port == r->actual_port)
            return r;
    }

    return NULL;
}

/* Bump the hit counter for a key from enum dns_hit_key. Atomic RMW
 * (__sync_fetch_and_add -> BPF_XADD) so a nested same-CPU invocation
 * (interrupt/softirq nesting between load and store) cannot lose an update;
 * also keeps the count correct if hit_cnt is ever a non-percpu map. */
static void count_hit(__u32 key)
{
    __u64 *cnt = bpf_map_lookup_elem(&hit_cnt, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

#endif /* DNS_CFG_H */