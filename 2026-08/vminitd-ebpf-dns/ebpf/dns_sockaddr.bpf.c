// dns_sockaddr.bpf.c — one multi-section BPF object for the DNS-redirect
// socket-layer hooks: connect4 + sendmsg4 (query redirect) and
// recvmsg4 (loopback answer rewrite), sharing one cfg_map and hit_cnt.
//
// Sections (each loads as its own BPF program, attached to its cgroup hook):
//   SEC("cgroup/connect4")  -> BPF_CGROUP_INET4_CONNECT (attach 10)
//   SEC("cgroup/sendmsg4")  -> BPF_CGROUP_UDP4_SENDMSG  (attach 14)
//   SEC("cgroup/recvmsg4")  -> BPF_CGROUP_UDP4_RECVMSG  (attach 19)
//
// All three share the cfg_map and keyed hit_cnt declared in dns_cfg.h;
// hit_cnt keys: 0 = connect4, 1 = sendmsg4, 2 = recvmsg4.
//
// Each rule is a self-contained redirect (requested <-> actual). match_rule()
// takes the direction explicitly:
//   DNS_QUERY  (connect4/sendmsg4): match the *requested* nameserver, rewrite
//                                   the destination to the *actual* upstream.
//   DNS_ANSWER (recvmsg4)         : match the *actual* source actually seen,
//                                   rewrite the reported source back to the
//                                   *requested* nameserver.
// One rule serves both directions of the same redirect.
//
// The recvmsg4 hook only rewrites the *reported* source in the socket layer, so
// the loopback source never touches the wire (no martian-drop / sysctls).

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "dns_cfg.h"

#define AF_INET 2

// Shared query-direction body: rewrite the destination to the actual
// upstream. Returns 1 when a rule matched (a hit to count).
static __u64 redirect_query(struct bpf_sock_addr *ctx)
{
    struct dns_rule *r;

    if (ctx->family != AF_INET)
        return 0;

    __u16 port = bpf_ntohs((__u16)ctx->user_port); /* __be16 in low 16 bits */
    r = match_rule(ctx->user_ip4, port, DNS_QUERY);
    if (!r)
        return 0;

    // ---- rewrite destination to the actual upstream ----
    ctx->user_ip4 = r->actual_ip;
    ctx->user_port = bpf_htons(r->actual_port);
    return 1;
}

SEC("cgroup/connect4")
int redirect_dns_query_connect(struct bpf_sock_addr *ctx)
{
    if (redirect_query(ctx))
        count_hit(DNS_HIT_CONNECT4);
    return SK_PASS;
}

SEC("cgroup/sendmsg4")
int redirect_dns_query_sendmsg(struct bpf_sock_addr *ctx)
{
    if (redirect_query(ctx))
        count_hit(DNS_HIT_SENDMSG4);
    return SK_PASS;
}

// Answer direction (recvmsg4): the kernel has delivered a datagram from
// the actual upstream; rewrite the *reported* source back to the requested
// nameserver so the resolver's identity check (musl memcmp's the sockaddr)
// passes. Never touches the wire, so no martian drop and no
// accept_local/route_localnet/rp_filter sysctls.
SEC("cgroup/recvmsg4")
int rewrite_answer_recvmsg(struct bpf_sock_addr *ctx)
{
    struct dns_rule *r;

    if (ctx->family != AF_INET)
        return SK_PASS;

    __u16 port = bpf_ntohs((__u16)ctx->user_port); /* __be16 in low 16 bits */
    r = match_rule(ctx->user_ip4, port, DNS_ANSWER);
    if (!r)
        return SK_PASS;

    // ---- report the source as the requested nameserver ----
    ctx->user_ip4 = r->requested_ip;
    ctx->user_port = bpf_htons(r->requested_port);

    count_hit(DNS_HIT_RECVMSG4);
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";