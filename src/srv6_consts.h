#ifndef __SRV6_CONSTS_H
#define __SRV6_CONSTS_H
#include "bpf_endian.h"
// linux/socket.h
#define AF_INET 2   /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/

// net/ipv6.h
#define NEXTHDR_ROUTING 43 /* Routing header. */

// Entry size
#define MAX_TXPORT_DEVICE 64
#define MAX_TRANSIT_ENTRIES 256
#define MAX_END_FUNCTION_ENTRIES 65536
#define MAX_SEGMENTS 5

//Encap define
#define SEG6_IPTUN_MODE_INLINE 0
#define SEG6_IPTUN_MODE_ENCAP 1
#define SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D 2
#define SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di 3
#define SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D 4
#define SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D 5

// Function define(e.g. Decap, segleft...)
#define SEG6_LOCAL_ACTION_END 1
#define SEG6_LOCAL_ACTION_END_X 2
#define SEG6_LOCAL_ACTION_END_T 3
#define SEG6_LOCAL_ACTION_END_DX2 4
#define SEG6_LOCAL_ACTION_END_DX6 5
#define SEG6_LOCAL_ACTION_END_DX4 6
#define SEG6_LOCAL_ACTION_END_DT6 7
#define SEG6_LOCAL_ACTION_END_DT4 8
#define SEG6_LOCAL_ACTION_END_B6 9
#define SEG6_LOCAL_ACTION_END_B6_ENCAPS 10
#define SEG6_LOCAL_ACTION_END_BM 11
#define SEG6_LOCAL_ACTION_END_S 12
#define SEG6_LOCAL_ACTION_END_AS 13
#define SEG6_LOCAL_ACTION_END_AM 14
#define SEG6_LOCAL_ACTION_T_M_GTP6_E 15
#define SEG6_LOCAL_ACTION_T_M_GTP4_E 16

#define IPV6_FLOWINFO_MASK __bpf_htonl(0x0FFFFFFF)

// GTP User Data Messages (GTPv1)
// 3GPP TS 29.060 "Table 1: Messages in GTP"
#define GTPV1_ECHO = 1;    // Echo Request
#define GTPV1_ECHORES = 2; // Echo Response
#define GTPV1_ERROR = 26;  // Error Indication
#define GTPV1_END = 254;   // End Marker
#define GTPV1_GPDU = 255;  // G-PDU

#endif
