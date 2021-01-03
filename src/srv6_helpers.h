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

__attribute__((__always_inline__)) static inline void write_v6addr_in_pyload(
    struct in6_addr *v6addr, __u8 *pyload, __u16 py_size, __u16 offset, __u16 shift, const __u32 *data_end)
{
    offset = offset & 0xffff;
    py_size = py_size & 0xffff;
    if (sizeof(struct in6_addr) <= offset ||
        sizeof(struct in6_addr) <= py_size + offset ||
        offset < 0)
        return;

    if (shift == 0)
    {
        if ((void *)v6addr + offset + py_size > data_end)
            return;

        __builtin_memcpy(&v6addr->in6_u.u6_addr8[offset], pyload, py_size);
    }
    /* TODO: 8 will also support the division case. help ebpf verify↓*/

    //     else
    //     {
    // #pragma clang loop unroll(disable)
    //         for (__u16 index = 0; index < sizeof(struct in6_addr); index++)
    //         {
    //             // index = index & 0xffff;

    //             if (py_size <= index)
    //                 break;

    //             if ((void *)v6addr + offset + index + 1 <= data_end)
    //             {
    //                 // v6addr->in6_u.u6_addr8[offset + index] |= pyload[index] >> shift;
    //                 v6addr->in6_u.u6_addr8[offset + index] = pyload[index];
    //             }

    //             // v6addr->in6_u.u6_addr8[offset + index + 1] |= pyload[index] << (8 - shift);
    //         }
    //     }
}

// struct sockaddr_in6 netmask;
// for (long i = prefixLength, j = 0; i > 0; i -= 8, ++j)
//   netmask.sin6_addr.s6_addr[ j ] = i >= 8 ? 0xff
//                                     : (ULONG)(( 0xffU << ( 8 - i ) ) & 0xffU );

/* from include/net/ip.h */
__attribute__((__always_inline__)) static inline int ip_decrease_ttl(struct iphdr *iph)
{
    __u32 check = (__u32)iph->check;

    check += (__u32)bpf_htons(0x0100);
    iph->check = (__sum16)(check + (check >= 0xFFFF));
    return --iph->ttl;
};

__attribute__((__always_inline__)) static inline void csum_update(struct iphdr *iph)
{
    __u16 *next_iph_u16;
    __u32 csum = 0;
    int i;
    iph->check = 0;
    next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(disable)
    for (i = 0; i < (sizeof(*iph) >> 1); i++)
        csum += *next_iph_u16++;

    iph->check = ~((csum & 0xffff) + (csum >> 16));
}

/* Function to set source and destination mac of the packet */
__attribute__((__always_inline__)) static inline void set_src_dst_mac(void *data, void *src, void *dst)
{
    unsigned short *source = src;
    unsigned short *dest = dst;
    unsigned short *p = data;

    __builtin_memcpy(p, dest, ETH_ALEN);
    __builtin_memcpy(p + 3, source, ETH_ALEN);
}

__attribute__((__always_inline__)) static inline struct srhhdr *get_srh(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct srhhdr *srh;
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
        bpf_printk("!get_ipv6 fail 1");
        return NULL;
    }

    if (v6h + 1 > data_end)
    {
        bpf_printk("!v6h + 1 > data_end fail 1");
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

__attribute__((__always_inline__)) static inline struct srhhdr *get_and_validate_srh(struct xdp_md *xdp)
{
    struct srhhdr *srh;

    srh = get_srh(xdp);
    if (!srh)
        return NULL;

    if (srh->segmentsLeft == 0)
        return NULL;

    // TODO
    // #ifdef CONFIG_IPV6_SEG6_HMAC
    // 	if (!seg6_hmac_validate_skb(skb))
    // 		return NULL;
    // #endif

    return srh;
}

__attribute__((__always_inline__)) static inline bool advance_nextseg(struct srhhdr *srh, struct in6_addr *daddr, struct xdp_md *xdp)
{
    struct in6_addr *addr;
    void *data_end = (void *)(long)xdp->data_end;

    srh->segmentsLeft--;
    if ((void *)(long)srh + sizeof(struct srhhdr) + sizeof(struct in6_addr) * (srh->segmentsLeft + 1) > data_end)
        return false;

    addr = srh->segments + srh->segmentsLeft;
    if (addr + 1 > data_end)
        return false;

    *daddr = *addr;
    return true;
}

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
    case BPF_FIB_LKUP_RET_BLACKHOLE: /* dest is blackholed; can be dropped */
        bpf_printk("BPF_FIB_LKUP_RET_BLACKHOLE");
        break;
    case BPF_FIB_LKUP_RET_UNREACHABLE: /* dest is unreachable; can be dropped */
        bpf_printk("BPF_FIB_LKUP_RET_UNREACHABLE");
        break;
    case BPF_FIB_LKUP_RET_PROHIBIT: /* dest not allowed; can be dropped */
        bpf_printk("BPF_FIB_LKUP_RET_PROHIBIT");
        break;
        // action = XDP_DROP;
        // return false;
    case BPF_FIB_LKUP_RET_NOT_FWDED: /* packet is not forwarded */
        bpf_printk("BPF_FIB_LKUP_RET_NOT_FWDED");
        break;
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
        bpf_printk("BPF_FIB_LKUP_RET_FWD_DISABLED");
        break;
    case BPF_FIB_LKUP_RET_UNSUPP_LWT: /* fwd requires encapsulation */
        bpf_printk("BPF_FIB_LKUP_RET_UNSUPP_LWT");
        break;
    case BPF_FIB_LKUP_RET_NO_NEIGH: /* no neighbor entry for nh */
        bpf_printk("BPF_FIB_LKUP_RET_NO_NEIGH");
        break;
    case BPF_FIB_LKUP_RET_FRAG_NEEDED: /* fragmentation required to fwd */
        bpf_printk("BPF_FIB_LKUP_RET_FRAG_NEEDED");
        break;
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
