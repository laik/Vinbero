#define KBUILD_MODNAME "xdp_srv6_functions"
#include <stdbool.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>
#include <linux/udp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#include "srv6_consts.h"
#include "srv6_structs.h"
#include "srv6_maps.h"
#include "srv6_helpers.h"
// #include "srv6_transit.h"

/* regular endpoint function */
__attribute__((__always_inline__)) static inline int action_end(struct xdp_md *xdp)
{
    bpf_printk("run action_end\n");
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct srhhdr *srhdr = get_and_validate_srh(xdp);
    struct ipv6hdr *v6h = get_ipv6(xdp);

    if (!srhdr || !v6h)
        return XDP_PASS;

    if (!advance_nextseg(srhdr, &v6h->daddr, xdp))
        return XDP_PASS;

    return rewrite_nexthop(xdp, 0);
}

__attribute__((__always_inline__)) static inline int base_decap(struct xdp_md *xdp, __u16 proto)
{
    void *data_end = (void *)(unsigned long)xdp->data_end;
    void *data = (void *)(unsigned long)xdp->data;

    struct srhhdr *srh = get_srh(xdp);
    struct ipv6hdr *v6h = get_ipv6(xdp);

    if (!srh || !v6h)
    {
        return XDP_PASS;
    }

    if (bpf_xdp_adjust_head(xdp, (int)(sizeof(struct ipv6hdr) + (srh->hdrExtLen + 1) * 8)))
    {
        return XDP_PASS;
    }

    data = (void *)(unsigned long)xdp->data;
    data_end = (void *)(unsigned long)xdp->data_end;
    struct ethhdr *new_eth = data;
    if (new_eth + 1 > data_end)
        return XDP_DROP;

    new_eth->h_proto = bpf_htons(proto);

    return NextFIBCheck;
}

__attribute__((__always_inline__)) static inline int action_enddx4(struct xdp_md *xdp, struct end_function *ef)
{
    int rc = base_decap(xdp, ETH_P_IPV4);
    if (rc != NextFIBCheck)
    {
        return rc;
    }

    void *data_end = (void *)(unsigned long)xdp->data_end;
    void *data = (void *)(unsigned long)xdp->data;
    struct iphdr *iph = get_ipv4(xdp);

    if (!iph)
    {
        return XDP_PASS;
    }

    iph->daddr = ef->nexthop.v4.addr;
    csum_update(iph);
    return rewrite_nexthop(xdp, 0);
}

__attribute__((__always_inline__)) static inline int base_encap(struct xdp_md *xdp, struct transit_behavior *tb, __u8 nexthdr, __u16 innerlen)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct ipv6hdr *v6h;
    struct srhhdr *srh;
    __u8 srh_len;

    srh_len = sizeof(struct srhhdr) + sizeof(struct in6_addr) * tb->segment_length;
    if (bpf_xdp_adjust_head(xdp, 0 - (int)(sizeof(struct ipv6hdr) + srh_len)))
        return XDP_PASS;

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;

    struct ethhdr *new_eth;
    new_eth = (void *)data;

    if ((void *)((long)new_eth + sizeof(struct ethhdr)) > data_end)
        return XDP_PASS;

    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    v6h = (void *)data + sizeof(struct ethhdr);
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) > data_end)
        return XDP_PASS;

    v6h->version = 6;
    v6h->priority = 0;
    v6h->nexthdr = NEXTHDR_ROUTING;
    v6h->hop_limit = 64;
    v6h->payload_len = bpf_htons(srh_len + innerlen);
    __builtin_memcpy(&v6h->saddr, &tb->saddr, sizeof(struct in6_addr));

    if (tb->segment_length == 0 || tb->segment_length > MAX_SEGMENTS)
        return XDP_PASS;

    __builtin_memcpy(&v6h->daddr, &tb->segments[tb->segment_length - 1], sizeof(struct in6_addr));

    srh = (void *)v6h + sizeof(struct ipv6hdr);
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct srhhdr)) > data_end)
        return XDP_PASS;

    srh->nextHdr = nexthdr;
    srh->hdrExtLen = ((srh_len / 8) - 1);
    srh->routingType = 4;
    srh->segmentsLeft = tb->segment_length - 1;
    srh->lastEntry = tb->segment_length - 1;
    srh->flags = 0;
    srh->tag = 0;

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < MAX_SEGMENTS; i++)
    {
        if (i >= tb->segment_length)
            break;

        if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct srhhdr) + sizeof(struct in6_addr) * (i + 1) + 1) > data_end)
            return XDP_PASS;

        __builtin_memcpy(&srh->segments[i], &tb->segments[i], sizeof(struct in6_addr));
    }

    return NextFIBCheck;
}

__attribute__((__always_inline__)) static inline int transit_encap(struct xdp_md *xdp, struct transit_behavior *tb, __u8 nexthdr, __u8 innerlen)
{
    int rc = base_encap(xdp, tb, nexthdr, innerlen);
    if (rc == NextFIBCheck)
        return rewrite_nexthop(xdp, BPF_FIB_LOOKUP_OUTPUT);
    return rc;
}

__attribute__((__always_inline__)) static inline int transit_gtp4_encap(struct xdp_md *xdp, struct transit_behavior *tb)
{
    bpf_printk("run transit_gtp4_encap str\n");

    // chack UDP/GTP packet
    void *data = (void *)(unsigned long)xdp->data;
    void *data_end = (void *)(unsigned long)xdp->data_end;
    struct iphdr *iph = get_ipv4(xdp);
    __u8 type;
    __u32 tid;
    __u16 seqNum;
    struct ipv6hdr *v6h;
    struct srhhdr *srh;
    __u8 srh_len;
    __u16 decap_len, encap_len;
    __u16 innerlen;
    __u32 outer_saddr, outer_daddr;
    if (!iph)
        return XDP_PASS;

    bpf_printk("run iph\n");

    // Check protocol
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    bpf_printk("run gtp1hdr\n");

    struct gtp1hdr *gtp1h = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtp1hdr) > data_end)
        return XDP_PASS;

    __builtin_memcpy(&outer_saddr, &iph->saddr, sizeof(__u32));
    __builtin_memcpy(&outer_daddr, &iph->daddr, sizeof(__u32));

    bpf_printk("run __builtin_memcpy(&outer_saddr, &iph->saddr, sizeof(__u32));\n");

    // TODO:: extention header support
    decap_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtp1hdr);

    tid = gtp1h->tid;
    type = gtp1h->type;
    innerlen = bpf_ntohs(gtp1h->length);
    // GTPV1_GPDU only logic
    if (type != GTPV1_GPDU)
        return XDP_DROP;

    if (tb->s_prefixlen == 0 || tb->d_prefixlen == 0 ||
        MAX_GTP4_SRCADDR_PREFIX < tb->s_prefixlen ||
        MAX_GTP4_DSTADDR_PREFIX < tb->d_prefixlen)
        return XDP_DROP;

    // if (type == ECHO_REQUEST || type == ECHO_RESPONSE){
    //     seqNum = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtp1hdr);

    //     if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtp1hdr) + sizeof(u16) > data_end){
    //         return XDP_PASS;
    //     }
    // }

    srh_len = sizeof(struct srhhdr) + sizeof(struct in6_addr) * (tb->segment_length + 1);
    encap_len = sizeof(struct ipv6hdr) + srh_len;

    // Shrink
    if (bpf_xdp_adjust_head(xdp, 0 - decap_len + encap_len))
        return XDP_PASS;

    bpf_printk("run bpf_xdp_adjust_head ed\n");

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;

    struct ethhdr *new_eth = (void *)data;
    if ((void *)((long)new_eth + sizeof(struct ethhdr)) > data_end)
        return XDP_PASS;

    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    v6h = (void *)data + sizeof(struct ethhdr);
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) > data_end)
        return XDP_PASS;

    v6h->version = 6;
    v6h->priority = 0;
    v6h->nexthdr = NEXTHDR_ROUTING;
    v6h->hop_limit = 64;
    v6h->payload_len = bpf_htons(srh_len + innerlen);
    __builtin_memcpy(&v6h->saddr, &tb->saddr, sizeof(struct in6_addr));
    if (tb->segment_length == 0 || tb->segment_length > MAX_SEGMENTS)
        return XDP_PASS;
    __builtin_memcpy(&v6h->daddr, &tb->segments[tb->segment_length - 1], sizeof(struct in6_addr));

    struct args_mob_session args;
    __u16 s_offset, s_shift, d_offset, d_shift;

    s_offset = tb->s_prefixlen / 8;
    s_shift = tb->s_prefixlen % 8;
    d_offset = tb->d_prefixlen / 8;
    d_shift = tb->d_prefixlen % 8;

    args.qfi = 0; //TODO::GTP-U extension header get QFI
    args.r = 0;
    args.u = 0;
    // args.qfi_r_u = 0;
    args.session.pdu_session_id = tid;

    // shift ipv4 addr append
    __u8 *src_p, *dst_p, *args_p;
    src_p = (__u8 *)&outer_saddr;
    dst_p = (__u8 *)&outer_daddr;
    args_p = (__u8 *)&args;
    // struct in6_addr v6daddr;
    // __builtin_memset(&v6daddr, 0, sizeof(v6daddr));
    write_v6addr_in_pyload(&v6h->saddr, src_p, sizeof(__u32), s_offset, s_shift, data_end);

    // __builtin_memcpy(&v6daddr, &v6h->daddr, sizeof(struct in6_addr));
    srh = (void *)v6h + sizeof(struct ipv6hdr);
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct srhhdr)) > data_end)
        return XDP_PASS;

    srh->nextHdr = IPPROTO_IPIP;
    srh->hdrExtLen = ((srh_len / 8) - 1);
    srh->routingType = 4;
    srh->segmentsLeft = tb->segment_length - 1;
    srh->lastEntry = tb->segment_length - 1;
    srh->flags = 0;
    srh->tag = 0;
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct srhhdr) + sizeof(struct in6_addr) * 2 + 1) > data_end)
        return XDP_PASS;

    __builtin_memcpy(&srh->segments[0], &tb->daddr, sizeof(struct in6_addr));
    write_v6addr_in_pyload(&srh->segments[0], dst_p, sizeof(__u32), d_offset, d_shift, data_end);
    d_offset += sizeof(__u32);
    write_v6addr_in_pyload(&v6h->daddr, args_p, sizeof(struct args_mob_session), d_offset, d_shift, data_end);

#pragma clang loop unroll(full)
    for (__u32 i = 1; i < MAX_SEGMENTS; i++)
    {
        if (i >= tb->segment_length)
            break;

        if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct srhhdr) + sizeof(struct in6_addr) * (i + 2) + 1) > data_end)
            return XDP_PASS;

        __builtin_memcpy(&srh->segments[i], &tb->segments[i - 1], sizeof(struct in6_addr));
    }

    return rewrite_nexthop(xdp, BPF_FIB_LOOKUP_OUTPUT);
}

__attribute__((__always_inline__)) static inline int action_end_m_gtp4_e(struct xdp_md *xdp, struct end_function *ef)
{
    return 0;
}
SEC("xdp_prog")
int srv6_handler(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph = get_ipv4(xdp);
    struct ipv6hdr *v6h = get_ipv6(xdp);
    struct end_function *ef_table;
    struct transit_behavior *tb;
    struct lpm_key_v4 v4key;
    struct lpm_key_v6 v6key;
    __u16 h_proto;

    if (data + sizeof(*eth) > data_end)
    {
        return xdpcap_exit(xdp, &xdpcap_hook, XDP_PASS);
    }
    if (!iph || !v6h)
    {
        return xdpcap_exit(xdp, &xdpcap_hook, XDP_PASS);
    }

    h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_IP))
    {
        // use encap
        v4key.prefixlen = 32;
        v4key.addr = iph->daddr;
        bpf_printk("check addr %x", iph->daddr);

        tb = bpf_map_lookup_elem(&transit_table_v4, &v4key);
        if (tb)
        {
            bpf_printk("check tb %x", tb->action);

            // segment size valid
            switch (tb->action)
            {
            case SEG6_IPTUN_MODE_ENCAP:
                bpf_printk("run SEG6_IPTUN_MODE_ENCAP\n");
                return xdpcap_exit(xdp, &xdpcap_hook, transit_encap(xdp, tb, IPPROTO_IPIP, bpf_ntohs(iph->tot_len)));

            case SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D:
                bpf_printk("run SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D\n");
                return xdpcap_exit(xdp, &xdpcap_hook, transit_gtp4_encap(xdp, tb));
            }
        }
    }
    else if (h_proto == bpf_htons(ETH_P_IPV6))
    {
        v6key.prefixlen = 128;
        v6key.addr = v6h->daddr;
        if (v6h->nexthdr == NEXTHDR_ROUTING)
        {
            // use nexthop and exec to function or decap or encap
            ef_table = bpf_map_lookup_elem(&function_table, &v6key);
            if (ef_table)
            {
                switch (ef_table->function)
                {
                case SEG6_LOCAL_ACTION_END:
                    return xdpcap_exit(xdp, &xdpcap_hook, action_end(xdp));
                case SEG6_LOCAL_ACTION_END_DX4:
                    return xdpcap_exit(xdp, &xdpcap_hook, action_enddx4(xdp, ef_table));
                case SEG6_LOCAL_ACTION_END_M_GTP4_E:
                    return xdpcap_exit(xdp, &xdpcap_hook, action_end_m_gtp4_e(xdp, ef_table));
                }
            }
        }
        else
        {
            // encap type code
            tb = bpf_map_lookup_elem(&transit_table_v6, &v6key);
            if (tb)
            {
                // segment size valid
                switch (tb->action)
                {
                case SEG6_IPTUN_MODE_ENCAP:
                    return xdpcap_exit(xdp, &xdpcap_hook, transit_encap(xdp, tb, IPPROTO_IPV6, v6h->payload_len));
                    // case SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D:
                    //     // bpf_printk("run SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D\n");
                    //     return xdpcap_exit(xdp, &xdpcap_hook, action_h_gtp4_d(xdp, tb));
                }
            }
        }
    }
    bpf_printk("no match all\n");
    return xdpcap_exit(xdp, &xdpcap_hook, XDP_PASS);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
