#define KBUILD_MODNAME "xdp_srv6_functions"

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>
#include <linux/socket.h>
#include <net/ipv6.h>
#include "bpf_helpers.h" // for bpf_trace_printk, SEC, bpf_map_def


// #include "srv6_maps.h"
// #include "srv6_structs.h"
// #include "srv6_consts.h"
#define IPV6_FLOWINFO_MASK cpu_to_be32(0x0FFFFFFF)
#define MAX_TRANSIT_ENTRIES 256
#define MAX_END_FUNCTION_ENTRIES 256
#define MAX_SEGMENTS 5


#define SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D 2		
#define SEG6_LOCAL_ACTION_T_M_GTP4_E 15


struct lookup_result {
    u32 ifindex;
    u8 smac[6];
    u8 dmac[6];
};

struct transit_behavior {
    u32 segment_length;
    struct in6_addr saddr;
    struct in6_addr segments[MAX_SEGMENTS];
};

struct end_function {
    u8 function;
};

struct gtp1hdr { /* According to 3GPP TS 29.060. */
    u8 flags;
    u8 type;
    u16 length;
    u32 tid;
};

// https://tools.ietf.org/html/draft-ietf-dmm-srv6-mobile-uplane-05#section-6.1
struct args_mob_session{ 
    u8 qfi : 6;
    u8 r : 1;
    u8 u : 1;
    u32 pdu_session_id;
};

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") transit_table_v4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct transit_behavior),
    .max_entries = MAX_TRANSIT_ENTRIES,
};

struct bpf_map_def SEC("maps") function_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct in6_addr),
    .value_size = sizeof(struct end_function),
    .max_entries = MAX_END_FUNCTION_ENTRIES,
};

static inline int check_lookup_result(struct lookup_result *result)
{
    if (result->dmac[0] == 0 || result->dmac[1] == 0 || result->dmac[2] == 0 || result->dmac[3] == 0 || result->dmac[4] == 0 ||
        result->dmac[5] == 0) {
        return 0;
    }
    return 1;
}

static inline struct ipv6_sr_hdr *get_srh(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct ipv6_sr_hdr *srh;
    int len, srhoff = 0;

    srh = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    if (srh + 1 > data_end) {
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

    if (data + sizeof(struct ethhdr) > data_end) {
        return NULL;
    }

    if (v6h + 1 > data_end) {
        return NULL;
    }

    return v6h;
};

static inline struct iphdr *get_ipv4(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) > data_end) {
        return NULL;
    }

    if (iph + 1 > data_end) {
        return NULL;
    }

    return iph;
};

static inline struct ipv6_sr_hdr *get_and_validate_srh(struct xdp_md *xdp)
{
    struct ipv6_sr_hdr *srh;

    srh = get_srh(xdp);
    if (!srh) {
        return NULL;
    }

    if (srh->segments_left == 0) {
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
    if ((void *)(long)srh + sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * (srh->segments_left + 1) > data_end) {
        return 0;
    }
    addr = srh->segments + srh->segments_left;
    *daddr = *addr;
    return 1;
}

// WIP: write by only ipv6 type
static inline struct lookup_result lookup_nexthop(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *v6h = get_ipv6(xdp);
    struct iphdr *iph = get_ipv4(xdp);

    struct bpf_fib_lookup fib_params;

    struct lookup_result result = {};
    u16 h_proto;

    if (data + sizeof(struct ethhdr) > data_end || !v6h || !iph) {
        memset(result.dmac, 0, sizeof(u8) * ETH_ALEN);
        return result;
    }

    h_proto = eth->h_proto;

    memset(&fib_params, 0, sizeof(fib_params));

    if (h_proto == htons(ETH_P_IPV6)) {
        struct in6_addr *src = (struct in6_addr *)fib_params.ipv6_src;
        struct in6_addr *dst = (struct in6_addr *)fib_params.ipv6_dst;
        // bpf_fib_lookup
        // flags: BPF_FIB_LOOKUP_DIRECT, BPF_FIB_LOOKUP_OUTPUT
        // https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h#L2611
        fib_params.family = AF_INET6;
        fib_params.tos = 0;
        fib_params.flowinfo = *(__be32 *)v6h & IPV6_FLOWINFO_MASK;
        fib_params.l4_protocol = v6h->nexthdr;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = ntohs(v6h->payload_len);
        *src = v6h->saddr;
        *dst = v6h->daddr;
    } else if (h_proto == htons(ETH_P_IP)) {
        fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.l4_protocol = iph->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = ntohs(iph->tot_len);
        fib_params.ipv4_src = iph->saddr;
        fib_params.ipv4_dst = iph->daddr;
    } else {
        memset(result.dmac, 0, sizeof(u8) * ETH_ALEN);
        return result;
    }

    fib_params.ifindex = xdp->ingress_ifindex;

    int rc = bpf_fib_lookup(xdp, &fib_params, sizeof(fib_params), 0);

    if (rc != 0) {
        memset(result.dmac, 0, sizeof(u8) * ETH_ALEN);
        return result;
    }
    result.ifindex = fib_params.ifindex;
    memcpy(result.dmac, fib_params.dmac, ETH_ALEN);
    memcpy(result.smac, fib_params.smac, ETH_ALEN);
    return result;
}

static inline int rewrite_nexthop(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    struct lookup_result result = lookup_nexthop(xdp);
    if (check_lookup_result(&result)) {
        memcpy(eth->h_dest, result.dmac, ETH_ALEN);
        memcpy(eth->h_source, result.smac, ETH_ALEN);
        if (xdp->ingress_ifindex == result.ifindex) {
            return XDP_TX;
        }
        // todo: fix bpf_redirect_map
        return bpf_redirect_map(&tx_port, result.ifindex, 0);
    }
    return XDP_PASS;
}

/* regular endpoint function */
static inline int action_end(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct ipv6_sr_hdr *srhdr = get_and_validate_srh(xdp);
    struct ipv6hdr *v6h = get_ipv6(xdp);

    if (!srhdr || !v6h) {
        return XDP_PASS;
    }
    if (advance_nextseg(srhdr, &v6h->daddr, xdp)) {
        return XDP_PASS;
    }

    return rewrite_nexthop(xdp);
}

SEC("xdp_prog")
int srv6_handler(struct xdp_md *xdp)
{
    bpf_printk("srv6_handler start");
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph = get_ipv4(xdp);
    struct ipv6hdr *v6h = get_ipv6(xdp);
    struct end_function *ef_table;

    u16 h_proto;

    if (data + sizeof(*eth) > data_end) {
        bpf_printk("data_end 1\n");
        return XDP_PASS;
    }
    if (!iph || !v6h) {
        bpf_printk("data_end 2\n");
        return XDP_PASS;
    }

    h_proto = eth->h_proto;
    bpf_printk("srv6_handler L3 check\n");
    if (h_proto == htons(ETH_P_IP)) {
        // use encap
        // ef_table = bpf_map_lookup_elem(&function_table, &iph->daddr);
        

    } else if (h_proto == htons(ETH_P_IPV6)) {
        // use nexthop and exec to function or decap or encap
        // checkSRv6
        if (v6h->nexthdr == NEXTHDR_ROUTING) {
            bpf_printk("match v6h->nexthdr == NEXTHDR_ROUTING)\n");
            ef_table = bpf_map_lookup_elem(&function_table, &(v6h->daddr));
            if (!ef_table) {
                int pt = 2;
                bpf_printk("not match ef_table 1 %llu",v6h->daddr.s6_addr32[0]);
                bpf_printk("not match ef_table 2 %llu",v6h->daddr.s6_addr32[1]);
                bpf_printk("not match ef_table 3 %llu",v6h->daddr.s6_addr32[2]);
                bpf_printk("not match ef_table 4 %llu",v6h->daddr.s6_addr32[3]);
                bpf_map_update_elem(&function_table, &(v6h->daddr), &pt, BPF_ANY);
                return XDP_PASS;
            }
            bpf_printk("ef_table check %u",ef_table);
            switch (ef_table->function) {
            case SEG6_LOCAL_ACTION_END:
                bpf_printk("run action_end\n");
                return action_end(xdp);
            }
        } else {
            // todo::
            // encap type code
            // encap check condtion 
        }
    }
    bpf_printk("no match all\n");
    return XDP_PASS;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
