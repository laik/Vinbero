#ifndef __SRV6_HELPERS_H
#define __SRV6_HELPERS_H

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

static inline int check_lookup_result(void *dest)
{
    unsigned short *dmac = dest;
    if (dmac[0] == 0 || dmac[1] == 0 || dmac[2] == 0 || dmac[3] == 0 || dmac[4] == 0 ||
        dmac[5] == 0)
    {
        return 0;
    }
    return 1;
}

/* Function to set source and destination mac of the packet */
static inline void set_src_dst_mac(void *data, void *src, void *dst)
{
    unsigned short *source = src;
    unsigned short *dest = dst;
    unsigned short *p = data;

    __builtin_memcpy(p, dest, 6);
    __builtin_memcpy(p + 3, source, 6);
}

static inline struct ipv6_sr_hdr *get_srh(struct xdp_md *xdp)
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

static inline struct ipv6hdr *get_ipv6(struct xdp_md *xdp)
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

static inline struct iphdr *get_ipv4(struct xdp_md *xdp)
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

static inline struct ipv6_sr_hdr *get_and_validate_srh(struct xdp_md *xdp)
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

static inline int advance_nextseg(struct ipv6_sr_hdr *srh, struct in6_addr *daddr, struct xdp_md *xdp)
{
    struct in6_addr *addr;
    void *data_end = (void *)(long)xdp->data_end;

    srh->segments_left--;
    if ((void *)(long)srh + sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * (srh->segments_left + 1) > data_end)
    {
        return 0;
    }
    addr = srh->segments + srh->segments_left;
    if (addr + 1 > data_end)
    {
        return 0;
    }
    *daddr = *addr;
    return 1;
}

// WIP: write by only ipv6 type
static inline void lookup_nexthop(struct xdp_md *xdp, void *source, void *dest, __u32 *ifindex)
{
    bpf_printk("run lookup_nexthop\n");
    unsigned short *smac = source;
    unsigned short *dmac = dest;
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *v6h = data + sizeof(struct ethhdr);
    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) > data_end)
    {
        __builtin_memset(dmac, 0, ETH_ALEN);
        return;
    }

    struct bpf_fib_lookup fib_params;

    __u16 h_proto;

    h_proto = eth->h_proto;
    __builtin_memset(&fib_params, 0, sizeof(fib_params));

    if (h_proto == bpf_htons(ETH_P_IP))
    {
        if (eth + sizeof(struct iphdr) > data_end)
        {
            __builtin_memset(dmac, 0, ETH_ALEN);
            return;
        }

        fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.l4_protocol = iph->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(iph->tot_len);
        fib_params.ipv4_src = iph->saddr;
        fib_params.ipv4_dst = iph->daddr;
    }
    else if (h_proto == bpf_htons(ETH_P_IPV6))
    {
        if (v6h + sizeof(struct ipv6hdr) > data_end)
        {
            __builtin_memset(dmac, 0, ETH_ALEN);
            return;
        }
        struct in6_addr *src = (struct in6_addr *)fib_params.ipv6_src;
        struct in6_addr *dst = (struct in6_addr *)fib_params.ipv6_dst;
        // bpf_fib_lookup
        // flags: BPF_FIB_LOOKUP_DIRECT, BPF_FIB_LOOKUP_OUTPUT
        // https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h#L2611
        if (v6h->hop_limit <= 1)
        {
            __builtin_memset(dmac, 0, ETH_ALEN);
            return;
        }
        fib_params.family = AF_INET6;
        fib_params.tos = 0;
        fib_params.flowinfo = *(__be32 *)v6h & IPV6_FLOWINFO_MASK;
        fib_params.l4_protocol = v6h->nexthdr;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(v6h->payload_len);
        *src = v6h->saddr;
        *dst = v6h->daddr;
    }
    else
    {
        __builtin_memset(dmac, 0, ETH_ALEN);
        return;
    }

    fib_params.ifindex = xdp->ingress_ifindex;

    int rc = bpf_fib_lookup(xdp, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);

    if (!rc)
    {
        __builtin_memset(dmac, 0, ETH_ALEN);
        return;
    }
    bpf_printk("fib_lookup success");
    *ifindex = fib_params.ifindex;
    __builtin_memcpy(dmac, fib_params.dmac, ETH_ALEN);
    __builtin_memcpy(smac, fib_params.smac, ETH_ALEN);
    return;
}
#endif
