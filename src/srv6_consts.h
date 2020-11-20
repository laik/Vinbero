#include "bpf_endian.h"

#ifndef __SRV6_CONSTS_H
#define __SRV6_CONSTS_H
// linux/socket.h
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/

// net/ipv6.h
#define NEXTHDR_ROUTING		43	/* Routing header. */

#define MAX_TRANSIT_ENTRIES 256
#define MAX_END_FUNCTION_ENTRIES 256
#define MAX_SEGMENTS 5

#define SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D 2
#define SEG6_LOCAL_ACTION_T_M_GTP4_E 15

#define IPV6_FLOWINFO_MASK __bpf_htonl(0x0FFFFFFF)

#endif
