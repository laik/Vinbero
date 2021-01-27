package internal

import (
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/kr/pretty"
	"github.com/pkg/errors"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/srv6"
)

func setV6addrHeep(m *ebpf.Map) (*srv6.V6addrHeepMap, error) {
	// txport map
	v6heep := srv6.MappingV6addrHeep(m)

	// write to redirect map
	h := []*srv6.V6addrHeep{}
	err := v6heep.Update(h, 0)
	if err != nil {
		fmt.Printf("Unable to Insert into eBPF map: %v", err)
		return nil, errors.WithStack(err)
	}
	return v6heep, nil
}

func setTxportDevice(c *config.InternalConfig, m *ebpf.Map) (*srv6.TxPortsMap, error) {
	// txport map
	txm := srv6.MappingTxPort(m)

	// write to redirect map
	for _, dev := range c.Devices {
		iface, err := net.InterfaceByName(dev)
		if err != nil {
			fmt.Printf("fail to interface: %v", dev)
			return nil, errors.WithStack(err)
		}
		fmt.Printf("%v : %v\n", dev, iface)
		err = txm.Update(srv6.TxPort{Iface: uint32(iface.Index)}, iface.Index)
		if err != nil {
			fmt.Printf("Unable to Insert into eBPF map: %v", err)
			return nil, errors.WithStack(err)
		}
	}
	return txm, nil
}

func setSrv6Function(c []config.FunctionsConfig, m *ebpf.Map) (*srv6.FunctionTablesMap, error) {
	fnm := srv6.MappingFunctionTable(m)

	for _, fn := range c {
		actId, err := srv6.Seg6LocalActionInt(fn.Action)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		_, cidr, err := net.ParseCIDR(fn.TriggerAddr)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		prefixlen, _ := cidr.Mask.Size()

		sip := net.ParseIP(fn.SAddr)
		var convip, startSip, nhpip [16]byte
		var flaverid uint32
		copy(convip[:], cidr.IP.To16())
		if sip != nil {
			copy(startSip[:], sip.To16())
		}

		nip := net.ParseIP(fn.Nexthop)
		switch actId {
		case srv6.SEG6_LOCAL_ACTION_END_DX4:
			copy(nhpip[:], nip.To4())
		case srv6.SEG6_LOCAL_ACTION_END_DX6:
			copy(nhpip[:], nip.To16())

		case srv6.SEG6_LOCAL_ACTION_END:
		case srv6.SEG6_LOCAL_ACTION_END_X:
		case srv6.SEG6_LOCAL_ACTION_END_T:
			flaverid, err = srv6.Seg6LocalFlaverInt(fn.Flaver)
			if err != nil {
				return nil, errors.WithStack(err)
			}
		}

		var v4Spos, v4Dpos uint32
		if actId == srv6.SEG6_LOCAL_ACTION_END_M_GTP4_E {
			pos, err := strconv.Atoi(fn.V4AddrSPos)
			v4Spos = uint32(pos)
			if err != nil {
				return nil, errors.WithStack(err)
			}

			pos, err = strconv.Atoi(fn.V4AddrDPos)
			v4Dpos = uint32(pos)
			if err != nil {
				return nil, errors.WithStack(err)
			}
		}

		err = fnm.Update(
			srv6.FunctionTable{
				Function:   actId,
				StartSaddr: startSip,
				Nexthop:    nhpip,
				Flaver:     flaverid,
				V4AddrSPos: v4Spos,
				V4AddrDPos: v4Dpos,
			},
			convip,
			uint32(prefixlen),
		)
		if err != nil {
			fmt.Printf("Unable to Insert into eBPF map: %v", err)
			return nil, errors.WithStack(err)
		}
		fmt.Printf("Insert into eBPF map seg6 action: %v", fn)
	}
	fmt.Printf("%# v\n", pretty.Formatter(fnm))

	return fnm, nil
}

func setTransitv4(c []config.Transitv4Config, m *ebpf.Map) (*srv6.TransitTablev4sMap, error) {
	tranv4 := srv6.MappingTransitTablev4(m)

	for _, t4 := range c {
		actId, err := srv6.Seg6EncapModeInt(t4.Action)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		_, cidr, err := net.ParseCIDR(t4.TriggerAddr)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		prefixlen, _ := cidr.Mask.Size()

		sip := net.ParseIP(t4.SAddr)
		var convip [4]byte
		copy(convip[:], cidr.IP.To4())

		var (
			actSip, actDip   [16]byte
			sPrefix, dPrefix uint32
		)
		if actId == srv6.SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D {
			_, srcCidr, err := net.ParseCIDR(t4.SAddr)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			copy(actSip[:], srcCidr.IP.To16())
			srcPrefixlen, _ := srcCidr.Mask.Size()
			sPrefix = uint32(srcPrefixlen)

			_, dstCidr, err := net.ParseCIDR(t4.DAddr)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			copy(actDip[:], dstCidr.IP.To16())
			dstPrefixlen, _ := dstCidr.Mask.Size()
			dPrefix = uint32(dstPrefixlen)
		} else {
			if sip != nil {
				copy(actSip[:], sip.To16())
			}
		}

		var newsegments [srv6.MAX_SEGMENTS][16]byte
		for i, seg := range t4.Segments {
			var segmentaddr [16]byte
			copy(segmentaddr[:], net.ParseIP(seg).To16())
			fmt.Println("segments addr", i, segmentaddr)
			newsegments[i] = segmentaddr
			fmt.Println("seg: ", newsegments[i])
		}
		fmt.Println("segment len is ", len(t4.Segments))
		err = tranv4.Update(
			srv6.TransitTablev4{
				Saddr:         actSip,
				Daddr:         actDip,
				SPrefixlen:    sPrefix,
				DPrefixlen:    dPrefix,
				SegmentLength: uint32(len(t4.Segments)),
				Action:        uint32(actId),
				Segments:      newsegments,
			},
			convip,
			uint32(prefixlen),
		)
		if err != nil {
			fmt.Printf("Unable to Insert into eBPF map: %v", err)
			return nil, errors.WithStack(err)
		}
	}
	fmt.Printf("%# v\n", pretty.Formatter(tranv4))

	return tranv4, nil
}

func setTransitv6(c []config.Transitv6Config, m *ebpf.Map) (*srv6.TransitTablev6sMap, error) {
	tranv6 := srv6.MappingTransitTablev6(m)

	for _, t6 := range c {
		actId, err := srv6.Seg6EncapModeInt(t6.Action)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		_, cidr, err := net.ParseCIDR(t6.TriggerAddr)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		prefixlen, _ := cidr.Mask.Size()

		sip := net.ParseIP(t6.SAddr)
		var convip [16]byte
		copy(convip[:], cidr.IP.To16())

		var (
			actSip, actDip   [16]byte
			sPrefix, dPrefix uint32
		)

		if sip != nil {
			copy(actSip[:], sip.To16())
		}

		var newsegments [srv6.MAX_SEGMENTS][16]byte
		for i, seg := range t6.Segments {
			var segmentaddr [16]byte
			copy(segmentaddr[:], net.ParseIP(seg).To16())
			fmt.Println("segments addr", i, segmentaddr)
			newsegments[i] = segmentaddr
			fmt.Println("seg: ", newsegments[i])
		}
		fmt.Println("segment len is ", len(t6.Segments))
		err = tranv6.Update(
			srv6.TransitTablev6{
				Saddr:         actSip,
				Daddr:         actDip,
				SPrefixlen:    sPrefix,
				DPrefixlen:    dPrefix,
				SegmentLength: uint32(len(t6.Segments)),
				Action:        uint32(actId),
				Segments:      newsegments,
			},
			convip,
			uint32(prefixlen),
		)
		if err != nil {
			fmt.Printf("Unable to Insert into eBPF map: %v", err)
			return nil, errors.WithStack(err)
		}
	}
	fmt.Printf("%# v\n", pretty.Formatter(tranv6))

	return tranv6, nil
}
