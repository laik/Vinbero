// https://github.com/vishvananda/netlink/blob/master/nl/seg6_linux.go
package srv6

import (
	"fmt"
	"net"
)

const (
	SEG6_GTPV1_LOC_FUNCTION_MAXSIZE = 56 // == 128 - v4addr(32) - args(40)
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
	SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D
	__SEG6_IPTUN_MODE_MAX
)

const (
	SEG6_IPTUN_MODE_MAX = __SEG6_IPTUN_MODE_MAX
)

// Helper functions
func Seg6EncapModeString(mode int) (string, error) {
	switch mode {
	case SEG6_IPTUN_MODE_INLINE:
		return "T.Insert", nil
	case SEG6_IPTUN_MODE_ENCAP:
		return "T.Encaps", nil
	case SEG6_IPTUN_MODE_L2ENCAP:
		return "T.Encaps.L2", nil
	case SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D:
		return "T.M.GTP6.D", nil
	case SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di:
		return "T.M.GTP6.D.Di", nil
	case SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D:
		return "H.M.GTP4.D", nil
	}
	return "", fmt.Errorf("%d mode number not match", mode)
}

func Seg6EncapModeInt(name string) (uint32, error) {
	switch name {
	case "SEG6_IPTUN_MODE_INLINE":
		return SEG6_IPTUN_MODE_INLINE, nil
	case "SEG6_IPTUN_MODE_ENCAP":
		return SEG6_IPTUN_MODE_ENCAP, nil
	case "SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D":
		return SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D, nil
	case "SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di":
		return SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di, nil
	case "SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D":
		return SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D, nil
	}
	return 0, fmt.Errorf("%d action not match", name)
}
