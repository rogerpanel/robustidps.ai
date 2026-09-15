/*
 * xdp_drop.bpf.c - RobustIDPS.ai edge agent XDP fast-path drop program
 *
 * This kernel-side eBPF program is loaded by the userspace agent (see
 * agent/agent-xdp/src/{lib.rs,main.rs}) via the `aya` crate and attached
 * to a NIC in XDP (driver / generic / offload) mode.
 *
 * Section: "xdp" (the program is `xdp_drop_blocked`).
 *
 * Maps (managed by userspace):
 *   - blocked_v4 : LPM_TRIE  key={prefixlen,u32 addr}      value=u8
 *   - blocked_v6 : LPM_TRIE  key={prefixlen,u8 addr[16]}   value=u8
 *   - stats      : ARRAY[4] of u64 counters
 *
 * For each ingress packet we:
 *   1. Bounds-check the ethernet header.
 *   2. Optionally peel a single 802.1Q / 802.1ad VLAN tag (no QinQ).
 *   3. For IPv4 / IPv6, build an LPM key from the source address and
 *      look it up in the corresponding blocked_* map. A hit -> XDP_DROP,
 *      a miss -> XDP_PASS. Anything else passes as STAT_PKT_NON_IP.
 *
 * IPv4 fragments and IPv6 extension headers do not affect the decision
 * because the source address lives in the fixed header in both cases.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

/* Stat indices - keep in sync with the userspace loader. */
#define STAT_PKT_TOTAL   0
#define STAT_PKT_DROPPED 1
#define STAT_PKT_PASSED  2
#define STAT_PKT_NON_IP  3
#define STAT_MAX         4

/* LPM key layouts. prefixlen MUST be the first field and host-endian; the
 * address bytes are stored in network byte order so a bytewise prefix
 * match by the kernel matches CIDR semantics. */
typedef struct {
    __u32 prefixlen;
    __u32 addr;          /* network byte order */
} lpm_v4_key_t;

typedef struct {
    __u32 prefixlen;
    __u8  addr[16];      /* network byte order */
} lpm_v6_key_t;

/* 802.1Q / 802.1ad tag (on the wire). */
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/* ---------------- Maps ---------------- */

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, lpm_v4_key_t);
    __type(value, __u8);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, lpm_v6_key_t);
    __type(value, __u8);
    __uint(max_entries, 8192);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
} stats SEC(".maps");

/* ---------------- Helpers ---------------- */

static __always_inline void stat_inc(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/* IPv4 source lookup. Returns 1 if the src is in blocked_v4. */
static __always_inline int v4_is_blocked(__be32 saddr_net)
{
    lpm_v4_key_t key;

    /* Explicit field-by-field stores keep the verifier happy: no
     * partially-initialised struct passes as a map key. */
    key.prefixlen = 32;
    key.addr      = saddr_net;   /* keep network byte order */

    return bpf_map_lookup_elem(&blocked_v4, &key) != NULL;
}

/* IPv6 source lookup. Returns 1 if the src is in blocked_v6. */
static __always_inline int v6_is_blocked(const struct in6_addr *saddr)
{
    lpm_v6_key_t key;
    int i;

    key.prefixlen = 128;
    #pragma unroll
    for (i = 0; i < 16; i++)
        key.addr[i] = saddr->in6_u.u6_addr8[i];

    return bpf_map_lookup_elem(&blocked_v6, &key) != NULL;
}

/* ---------------- Program ---------------- */

SEC("xdp")
int xdp_drop_blocked(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    stat_inc(STAT_PKT_TOTAL);

    __be16 proto = eth->h_proto;
    void  *l3    = (void *)(eth + 1);

    /* Peel exactly one VLAN tag (single-tagged 802.1Q or 802.1ad).
     * We deliberately do NOT chase nested QinQ tags - that path is
     * verifier-hostile and rare on production NICs. */
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vh = l3;
        if ((void *)(vh + 1) > data_end)
            return XDP_PASS;
        proto = vh->h_vlan_encapsulated_proto;
        l3    = (void *)(vh + 1);
    }

    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = l3;
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        if (v4_is_blocked(iph->saddr)) {
            stat_inc(STAT_PKT_DROPPED);
            return XDP_DROP;
        }
        stat_inc(STAT_PKT_PASSED);
        return XDP_PASS;
    }

    if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = l3;
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        if (v6_is_blocked(&ip6h->saddr)) {
            stat_inc(STAT_PKT_DROPPED);
            return XDP_DROP;
        }
        stat_inc(STAT_PKT_PASSED);
        return XDP_PASS;
    }

    /* ARP, MPLS, LLDP, raw 802.3 ... we don't classify; pass through. */
    stat_inc(STAT_PKT_NON_IP);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
