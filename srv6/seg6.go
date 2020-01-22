// https://github.com/vishvananda/netlink/blob/master/nl/seg6_linux.go
package srv6

import (
	"net"
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
	SEG6_IPTUN_MODE_ENCAP //1
	SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D   //2
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


// Helper functions
func SEG6EncapModeString(mode int) string {
	switch mode {
	case SEG6_IPTUN_MODE_INLINE:
		return "inline"
	case SEG6_IPTUN_MODE_ENCAP:
		return "encap"
	case SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D:
		return "T.M.GTP4.D"
	}
	return "unknown"
}

func SEG6EncapModeInt(name string) uint8 {
	switch name {
	case "SEG6_IPTUN_MODE_INLINE":
		return SEG6_IPTUN_MODE_INLINE
	case "SEG6_IPTUN_MODE_ENCAP":
		return SEG6_IPTUN_MODE_INLINE
	case "SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D":
		return SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D
	}
	return SEG6_IPTUN_MODE_MAX
}
