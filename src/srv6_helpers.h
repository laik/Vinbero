#ifndef __SRV6_HELPERS_H
#define __SRV6_HELPERS_H

#include <stdbool.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "srv6_consts.h"

/* from include/net/ip.h */
__attribute__((__always_inline__)) static inline int ip_decrease_ttl(struct iphdr *iph)
{
    __u32 check = (__u32)iph->check;

    check += (__u32)bpf_htons(0x0100);
    iph->check = (__sum16)(check + (check >= 0xFFFF));
    return --iph->ttl;
};

/* Function to set source and destination mac of the packet */
__attribute__((__always_inline__)) static inline void set_src_dst_mac(void *data, void *src, void *dst)
{
    unsigned short *source = src;
    unsigned short *dest = dst;
    unsigned short *p = data;

    __builtin_memcpy(p, dest, ETH_ALEN);
    __builtin_memcpy(p + 3, source, ETH_ALEN);
}

__attribute__((__always_inline__)) static inline struct ipv6_sr_hdr *get_srh(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct ipv6_sr_hdr *srh;
    int len, srhoff = 0;

    srh = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if (srh + 1 > data_end)
    {
        return NULL;
    }
    // len = (srh->hdrlen + 1) << 3;

    return srh;
}

__attribute__((__always_inline__)) static inline struct ipv6hdr *get_ipv6(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct ipv6hdr *v6h = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) > data_end)
    {
        return NULL;
    }

    if (v6h + 1 > data_end)
    {
        return NULL;
    }

    return v6h;
};

__attribute__((__always_inline__)) static inline struct iphdr *get_ipv4(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) > data_end)
    {
        return NULL;
    }

    if (iph + 1 > data_end)
    {
        return NULL;
    }

    return iph;
};

__attribute__((__always_inline__)) static inline struct ipv6_sr_hdr *get_and_validate_srh(struct xdp_md *xdp)
{
    struct ipv6_sr_hdr *srh;

    srh = get_srh(xdp);
    if (!srh)
    {
        return NULL;
    }

    if (srh->segments_left == 0)
    {
        return NULL;
    }

    // TODO
    // #ifdef CONFIG_IPV6_SEG6_HMAC
    // 	if (!seg6_hmac_validate_skb(skb))
    // 		return NULL;
    // #endif

    return srh;
}

__attribute__((__always_inline__)) static inline bool advance_nextseg(struct ipv6_sr_hdr *srh, struct in6_addr *daddr, struct xdp_md *xdp)
{
    struct in6_addr *addr;
    void *data_end = (void *)(long)xdp->data_end;

    srh->segments_left--;
    if ((void *)(long)srh + sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * (srh->segments_left + 1) > data_end)
    {
        return false;
    }
    addr = srh->segments + srh->segments_left;
    if (addr + 1 > data_end)
    {
        return false;
    }
    *daddr = *addr;
    return true;
}

// WIP: write by only ipv6 type
__attribute__((__always_inline__)) static inline bool lookup_nexthop(struct xdp_md *xdp, void *smac, void *dmac, __u32 *ifindex, __u32 flag)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph = get_ipv4(xdp);
    struct ipv6hdr *v6h = get_ipv6(xdp);
    struct bpf_fib_lookup fib_params = {};
    __u16 h_proto;
    //TODO:: impl dot1q proto
    if (data + sizeof(struct ethhdr) > data_end)
        return false;

    if (!iph || !v6h)
        return false;

    h_proto = eth->h_proto;
    __builtin_memset(&fib_params, 0, sizeof(fib_params));

    switch (h_proto)
    {
    case bpf_htons(ETH_P_IP):
        fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.l4_protocol = iph->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(iph->tot_len);
        fib_params.ipv4_src = iph->saddr;
        fib_params.ipv4_dst = iph->daddr;
        break;

    case bpf_htons(ETH_P_IPV6):
        if (v6h->hop_limit <= 1)
            return false;

        struct in6_addr *src = (struct in6_addr *)fib_params.ipv6_src;
        struct in6_addr *dst = (struct in6_addr *)fib_params.ipv6_dst;

        fib_params.family = AF_INET6;
        fib_params.tos = 0;
        fib_params.flowinfo = *(__be32 *)v6h & IPV6_FLOWINFO_MASK;
        fib_params.l4_protocol = v6h->nexthdr;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(v6h->payload_len);
        *src = v6h->saddr;
        *dst = v6h->daddr;
        break;

    default:
        return false;
    }

    // bpf_fib_lookup
    // flags: BPF_FIB_LOOKUP_DIRECT, BPF_FIB_LOOKUP_OUTPUT
    // https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h#L2611
    fib_params.ifindex = xdp->ingress_ifindex;
    // int rc = bpf_fib_lookup(xdp, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
    int rc = bpf_fib_lookup(xdp, &fib_params, sizeof(fib_params), flag);

    switch (rc)
    {
    case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
        if (h_proto == bpf_htons(ETH_P_IP))
            ip_decrease_ttl(iph);
        else if (h_proto == bpf_htons(ETH_P_IPV6))
            v6h->hop_limit--;

        *ifindex = fib_params.ifindex;

        __u8 *source = smac;
        __u8 *dest = dmac;
        __builtin_memcpy(dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(source, fib_params.smac, ETH_ALEN);
        return true;
    case BPF_FIB_LKUP_RET_BLACKHOLE:   /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:    /* dest not allowed; can be dropped */
        // action = XDP_DROP;
        // return false;
    case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
        /* PASS */
        return false;
    }
    return false;
}

__attribute__((__always_inline__)) static inline int rewrite_nexthop(struct xdp_md *xdp, __u32 flag)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
    {
        return XDP_PASS;
    }

    __u32 ifindex;
    __u8 smac[6], dmac[6];

    bool is_exist = lookup_nexthop(xdp, &smac, &dmac, &ifindex, flag);
    if (is_exist)
    {
        set_src_dst_mac(data, &smac, &dmac);
        if (!bpf_map_lookup_elem(&tx_port, &ifindex))
            return XDP_PASS;

        if (xdp->ingress_ifindex == ifindex)
        {
            bpf_printk("run tx");
            return XDP_TX;
        }
        bpf_printk("go to redirect");
        return bpf_redirect_map(&tx_port, ifindex, 0);
    }
    bpf_printk("failed rewrite nhop");
    return XDP_PASS;
}

#endif
