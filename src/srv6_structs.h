#ifndef __SRV6_STRUCTS_H
#define __SRV6_STRUCTS_H
#include "srv6_consts.h"

struct lookup_result {
    __u32 ifindex;
    __u8 smac[6];
    __u8 dmac[6];
};

struct transit_behavior {
    __u8 action;
    __u32 segment_length;
    struct in6_addr saddr;
    struct in6_addr segments[MAX_SEGMENTS];
};

struct end_function {
    __u8 function;
};

struct gtp1hdr { /* According to 3GPP TS 29.060. */
    __u8 flags;
    __u8 type;
    __u16 length;
    __u32 tid;
    //u16 seqNum;
};

// https://tools.ietf.org/html/draft-ietf-dmm-srv6-mobile-uplane-05#section-6.1
struct args_mob_session{
    __u8 qfi : 6;
    __u8 r : 1;
    __u8 u : 1;
    __u32 pdu_session_id;
};



#endif
