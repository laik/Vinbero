// https://github.com/vishvananda/netlink/blob/master/nl/seg6_linux.go
package srv6

import (
	"net"
)

const (
	SEG6_GTPV1_LOC_FUNCTION_MAXSIZE_ = 56 // == 128 - v4addr(32) - args(40)
	SEG6_GTPV1_LOC_FUNCTION_MAXSIZE
)

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
	SEG6_IPTUN_MODE_ENCAP
	SEG6_IPTUN_MODE_L2ENCAP
	SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D
	SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di
	SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D
	SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D
	__SEG6_IPTUN_MODE_MAX
)

const (
	SEG6_IPTUN_MODE_MAX = __SEG6_IPTUN_MODE_MAX
)

const SEG6_IPTUN_MODE_UNKNOWN = "unknown"

// Helper functions
func Seg6EncapModeString(mode int) string {
	switch mode {
	case SEG6_IPTUN_MODE_INLINE:
		return "T.Insert"
	case SEG6_IPTUN_MODE_ENCAP:
		return "T.Encaps"
	case SEG6_IPTUN_MODE_L2ENCAP:
		return "T.Encaps.L2"
	case SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D:
		return "T.M.GTP6.D"
	case SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di:
		return "T.M.GTP6.D.Di"
	case SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D:
		return "T.M.GTP4.D"
	case SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D:
		return "H.M.GTP4.D"
	}
	return SEG6_IPTUN_MODE_UNKNOWN
}

func Seg6EncapModeInt(name string) uint8 {
	switch name {
	case "SEG6_IPTUN_MODE_INLINE":
		return SEG6_IPTUN_MODE_INLINE
	case "SEG6_IPTUN_MODE_ENCAP":
		return SEG6_IPTUN_MODE_ENCAP
	case "SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D":
		return SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D
	case "SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di":
		return SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di
	case "SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D":
		return SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D
	}
	return SEG6_IPTUN_MODE_MAX
}
