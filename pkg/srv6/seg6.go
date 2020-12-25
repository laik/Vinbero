// https://github.com/vishvananda/netlink/blob/master/nl/seg6_linux.go
package srv6

import (
	"net"
)

const SEG6_GTPV1_LOC_FUNCTION_MAXSIZE = 56 // == 128 - v4addr(32) - args(40)

type IPv6SrHdr struct {
	nextHdr      uint8
	hdrLen       uint8
	routingType  uint8
	segmentsLeft uint8
	firstSegment uint8
	flags        uint8
	reserved     uint16

	Segments []net.IP
}

// seg6 encap mode
const (
	SEG6_IPTUN_MODE_INLINE = iota
	SEG6_IPTUN_MODE_ENCAP  //1
	SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D
	SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di
	SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D
	SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D
	__SEG6_IPTUN_MODE_MAX
)

const (
	SEG6_IPTUN_MODE_MAX = __SEG6_IPTUN_MODE_MAX
)

// number of nested RTATTR
// from include/uapi/linux/seg6_iptunnel.h
const (
	SEG6_IPTUNNEL_UNSPEC = iota
	SEG6_IPTUNNEL_SRH
	__SEG6_IPTUNNEL_MAX
)
const (
	SEG6_IPTUNNEL_MAX = __SEG6_IPTUNNEL_MAX - 1
)

const SEG6_ENCAP_MODE_UNKNOWN = "unknown"

// Helper functions
func SEG6EncapModeString(mode int) string {
	switch mode {
	case SEG6_IPTUN_MODE_INLINE:
		return "inline"
	case SEG6_IPTUN_MODE_ENCAP:
		return "encap"
	case SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D:
		return "T.M.GTP6.D"
	case SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di:
		return "T.M.GTP6.D.Di"
	case SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D:
		return "T.M.GTP4.D"
	case SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D:
		return "H.M.GTP4.D"
	}
	return SEG6_ENCAP_MODE_UNKNOWN
}

func SEG6EncapModeInt(name string) uint8 {
	switch name {
	case "SEG6_IPTUN_MODE_INLINE":
		return SEG6_IPTUN_MODE_INLINE
	case "SEG6_IPTUN_MODE_ENCAP":
		return SEG6_IPTUN_MODE_INLINE
	case "SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D":
		return SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D
	case "SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di":
		return SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di
	case "SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D":
		return SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D
	}
	return SEG6_IPTUN_MODE_MAX
}
