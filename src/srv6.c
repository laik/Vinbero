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

// linux/socket.h
#define AF_INET 2   /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/

// net/ipv6.h
#define NEXTHDR_ROUTING 43 /* Routing header. */

#include "srv6_consts.h"
#include "srv6_structs.h"
#include "srv6_maps.h"
#include "srv6_helpers.h"

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
        bpf_printk("!srh || !v6h SEG6_LOCAL_ACTION_END_DX4 fetch iph failed");
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
        bpf_printk("base_decap SEG6_LOCAL_ACTION_END_DX4 fetch iph failed");
        return rc;
    }

    void *data_end = (void *)(unsigned long)xdp->data_end;
    void *data = (void *)(unsigned long)xdp->data;
    struct iphdr *iph = get_ipv4(xdp);

    if (!iph)
    {
        bpf_printk("go SEG6_LOCAL_ACTION_END_DX4 fetch iph failed");
        return XDP_PASS;
    }

    iph->daddr = ef->nexthop.v4.addr;
    csum_update(iph);
    return rewrite_nexthop(xdp, 0);
}

__attribute__((__always_inline__)) static inline int base_encap(struct xdp_md *xdp, struct transit_behavior *tb, __u8 nexthdr, __u8 innerlen)
{
    bpf_printk("run action_end\n");
    void *data = (void *)(unsigned long)xdp->data;
    void *data_end = (void *)(unsigned long)xdp->data_end;

    struct ipv6hdr *hdr;
    struct srhhdr *srh;
    __u8 srh_len;

    srh_len = sizeof(struct srhhdr) + sizeof(struct in6_addr) * tb->segment_length;
    if (bpf_xdp_adjust_head(xdp, 0 - (int)(sizeof(struct ipv6hdr) + srh_len)))
        return XDP_PASS;

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;

    struct ethhdr *old_eth, *new_eth;
    new_eth = (void *)data;
    old_eth = (void *)(data + sizeof(struct ipv6hdr) + srh_len);
    if ((void *)((long)old_eth + sizeof(struct ethhdr)) > data_end)
        return XDP_PASS;

    if ((void *)((long)new_eth + sizeof(struct ethhdr)) > data_end)
        return XDP_PASS;

    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    hdr = (void *)data + sizeof(struct ethhdr);
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) > data_end)
    {
        return XDP_PASS;
    }
    hdr->version = 6;
    hdr->priority = 0;
    hdr->nexthdr = NEXTHDR_ROUTING;
    hdr->hop_limit = 64;
    hdr->payload_len = bpf_htons(srh_len + innerlen);
    __builtin_memcpy(&hdr->saddr, &tb->saddr, sizeof(struct in6_addr));
    if (tb->segment_length == 0 || tb->segment_length > MAX_SEGMENTS)
        return XDP_PASS;

    __builtin_memcpy(&hdr->daddr, &tb->segments[tb->segment_length - 1], sizeof(struct in6_addr));

    srh = (void *)hdr + sizeof(struct ipv6hdr);
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct srhhdr)) > data_end)
        return XDP_PASS;

    srh->nextHdr = nexthdr;
    srh->hdrExtLen = ((srh_len / 8) - 1);
    srh->routingType = 4;
    srh->segmentsLeft = tb->segment_length - 1;
    srh->lastEntry = tb->segment_length - 1;
    srh->flags = 0;

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < MAX_SEGMENTS; i++)
    {
        if (tb->segment_length <= i)
            break;

        if ((void *)(&srh->segments[i] + sizeof(struct in6_addr) + 1) > data_end)
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

/* regular endpoint function */
__attribute__((__always_inline__)) static inline int action_t_gtp4_d(struct xdp_md *xdp, struct transit_behavior *tb)
{
    // chack UDP/GTP packet
    void *data = (void *)(unsigned long)xdp->data;
    void *data_end = (void *)(unsigned long)xdp->data_end;
    struct iphdr *iph = get_ipv4(xdp);
    __u8 type;
    __u32 tid;
    __u16 seqNum;
    if (!iph)
    {
        return XDP_PASS;
    }
    __u16 inner_len = bpf_ntohs(iph->tot_len);

    // Check protocol
    bpf_printk("Check protocol\n");
    if (iph->protocol != IPPROTO_UDP)
    {
        return XDP_PASS;
    }
    struct gtp1hdr *gtp1h = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtp1hdr) > data_end)
    {
        return XDP_PASS;
    }

    // tid = gtp1h->tid;
    // type = gtp1h -> type;
    // if (type == ECHO_REQUEST || type == ECHO_RESPONSE){
    //     seqNum = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtp1hdr);

    //     if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtp1hdr) + sizeof(u16) > data_end){
    //         return XDP_PASS;
    //     }
    // }

    // new seg6 headers
    struct ipv6hdr *hdr;
    struct ipv6_sr_hdr *srh;
    __u8 srh_len;
    bpf_printk("new seg6 headers start\n");

    if (tb->segment_length > MAX_SEGMENTS)
    {
        return XDP_PASS;
    }
    srh_len = sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * tb->segment_length;
    if (bpf_xdp_adjust_head(xdp, 0 - (int)(sizeof(struct ipv6hdr) + srh_len)))
    {
        return XDP_PASS;
    }
    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;

    if (!iph)
    {
        return XDP_PASS;
    }
    bpf_printk("new seg6 make hdr\n");
    struct ethhdr *old_eth, *new_eth;
    new_eth = (void *)data;
    old_eth = (void *)(data + sizeof(struct ipv6hdr) + srh_len);
    if ((void *)((long)old_eth + sizeof(struct ethhdr)) > data_end)
    {
        return XDP_PASS;
    }
    if ((void *)((long)new_eth + sizeof(struct ethhdr)) > data_end)
    {
        return XDP_PASS;
    }
    __builtin_memcpy(&new_eth->h_source, &old_eth->h_dest, sizeof(unsigned char) * ETH_ALEN);
    __builtin_memcpy(&new_eth->h_dest, &old_eth->h_source, sizeof(unsigned char) * ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    // outer IPv6 header
    bpf_printk("outer IPv6 header\n");
    hdr = (void *)data + sizeof(struct ethhdr);
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) > data_end)
    {
        return XDP_PASS;
    }
    hdr->version = 6;
    hdr->priority = 0;
    hdr->nexthdr = NEXTHDR_ROUTING;
    hdr->hop_limit = 64;
    hdr->payload_len = bpf_htons(srh_len + inner_len);
    __builtin_memcpy(&hdr->saddr, &tb->saddr, sizeof(struct in6_addr));
    if (tb->segment_length == 0 || tb->segment_length > MAX_SEGMENTS)
    {
        return XDP_PASS;
    }
    __builtin_memcpy(&hdr->daddr, &tb->segments[tb->segment_length - 1], sizeof(struct in6_addr));

    srh = (void *)hdr + sizeof(struct ipv6hdr);
    if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct ipv6_sr_hdr)) > data_end)
    {
        return XDP_PASS;
    }
    srh->nexthdr = IPPROTO_IPIP;
    srh->hdrlen = (srh_len / 8 - 1);
    srh->type = 4;
    srh->segments_left = tb->segment_length - 1;
    srh->first_segment = tb->segment_length - 1;
    srh->flags = 0;

    bpf_printk("loop write\n");
#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_SEGMENTS; i++)
    {
        if (tb->segment_length <= i)
        {
            break;
        }
        if (tb->segment_length == i - 1)
        {
            // todo :: convation ipv6 addr
        }
        if ((void *)(&srh->segments[i] + sizeof(struct in6_addr) + 1) > data_end)
            return XDP_PASS;

        __builtin_memcpy(&srh->segments[i], &tb->segments[i], sizeof(struct in6_addr));
    }

    bpf_printk("exec nexthop\n");
    return rewrite_nexthop(xdp, 0);
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
        tb = bpf_map_lookup_elem(&transit_table_v4, &v4key);
        if (tb)
        {
            // segment size valid
            switch (tb->action)
            {
            case SEG6_IPTUN_MODE_ENCAP:
                return xdpcap_exit(xdp, &xdpcap_hook, transit_encap(xdp, tb, IPPROTO_IPIP, iph->tot_len));

            case SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D:
                return xdpcap_exit(xdp, &xdpcap_hook, action_t_gtp4_d(xdp, tb));
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
                    bpf_printk("go SEG6_LOCAL_ACTION_END_DX4");
                    return xdpcap_exit(xdp, &xdpcap_hook, action_enddx4(xdp, ef_table));
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
                case SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D:
                    // bpf_printk("run SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D\n");
                    return xdpcap_exit(xdp, &xdpcap_hook, action_t_gtp4_d(xdp, tb));
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
