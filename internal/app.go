package internal

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/kr/pretty"
	"github.com/pkg/errors"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/coreelf"
	"github.com/takehaya/vinbero/pkg/srv6"
	"github.com/takehaya/vinbero/pkg/xdptool"
)

func App(c *config.Config) error {
	xdptool.PossibleCpuInit()
	obj, err := coreelf.ReadCollection()
	if err != nil {
		return errors.WithStack(err)
	}

	for _, dev := range c.InternalConfig.Devices {
		err = xdptool.Attach(obj.ProgramSrv6Handler, dev)
		if err != nil {
			return errors.WithStack(err)
		}
		// err = xdptool.Attach(obj.ProgramXdpPassFunc, dev)
		// if err != nil {
		// 	return errors.WithStack(err)
		// }
		log.Println("attached device: ", dev)
	}

	xdpcapHook := obj.MapXdpcapHook
	path := "/sys/fs/bpf/xdpcap_hook"
	os.RemoveAll(path)
	err = xdpcapHook.Pin(path)
	if err != nil {
		return errors.WithStack(err)
	}
	fmt.Printf("%# v\n", pretty.Formatter(c))

	txm, err := setTxportDevice(&c.InternalConfig, obj.MapTxPort)
	if err != nil {
		return errors.WithStack(err)
	}
	var srfn *srv6.FunctionTablesMap
	fmt.Printf("%# v\n", pretty.Formatter(txm))

	if funcs := c.Setting.Functions; 0 < len(funcs) {
		srfn, err = setSrv6Function(funcs, obj.MapFunctionTable)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	fmt.Printf("%# v\n", pretty.Formatter(srfn))

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	log.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	log.Println("Press CTRL+C to stop.")
	for {
		select {
		// case <-ticker.C:
		// fmt.Println("IP DROPs")
		// for i := 0; i < len(ipList); i++ {
		// 	value, err := ma.Get(uint32(i))
		// 	if err != nil {
		// 		fmt.Printf("LookupInt failed: %v", err)
		// 	}
		// 	fmt.Printf("%18s    %d\n", ipList[i], value)
		// }
		// fmt.Println()
		case <-signalChan:
			// TODO: change prepare priority elf->ebpfmap make -> xdp attach
			for _, dev := range c.InternalConfig.Devices {
				// Attach to interface
				err = xdptool.Detach(dev)
				if err != nil {
					return errors.WithStack(err)
				}
				log.Println("attached device: ", dev)
			}
			log.Println("Detaching program and exit")

			return nil
		}
	}
}

func setTxportDevice(c *config.InternalConfig, m *ebpf.Map) (*srv6.TxPortsMap, error) {
	// txport map
	txm := srv6.MappingTxPort(m)

	// write to redirect map
	for _, dev := range c.Devices {
		iface, err := net.InterfaceByName(dev)
		if err != nil {
			log.Printf("fail to interface: %v", dev)
			return nil, errors.WithStack(err)
		}
		fmt.Printf("%v : %v\n", dev, iface)
		err = txm.Update(srv6.TxPort{Iface: iface.Index}, iface.Index)
		if err != nil {
			log.Printf("Unable to Insert into eBPF map: %v", err)
			return nil, errors.WithStack(err)
		}
	}
	return txm, nil
}

func setSrv6Function(c []config.FunctionsConfig, m *ebpf.Map) (*srv6.FunctionTablesMap, error) {
	fnm := srv6.MappingFunctionTable(m)

	for _, fn := range c {
		actId := srv6.Seg6LocalActionInt(fn.Action)
		if srv6.SEG6_LOCAL_ACTION_MAX == actId {
			return nil, errors.New(fmt.Sprintf("%v not found", fn.Action))
		}
		_, cidr, err := net.ParseCIDR(fn.Addr)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		prefixlen, _ := cidr.Mask.Size()

		sip := net.ParseIP(fn.SAddr)
		var convip, startSip, nhpip [16]byte
		copy(convip[:], cidr.IP.To16())
		if sip != nil {
			copy(startSip[:], sip.To16())
		}
		switch actId {
		case srv6.SEG6_LOCAL_ACTION_END_DX4:
			nip := net.ParseIP(fn.Nexthop)
			copy(nhpip[:], nip.To4())
		case srv6.SEG6_LOCAL_ACTION_END_DX6:
			nip := net.ParseIP(fn.Nexthop)
			copy(nhpip[:], nip.To16())
		}

		err = fnm.Update(
			srv6.FunctionTable{
				Function:   uint32(actId),
				StartSaddr: startSip,
				Nexthop:    nhpip,
			},
			convip,
			uint32(prefixlen),
		)
		if err != nil {
			log.Printf("Unable to Insert into eBPF map: %v", err)
			return nil, errors.WithStack(err)
		}
		log.Printf("Insert into eBPF map seg6 action: %v", fn)
	}
	fmt.Printf("%# v\n", pretty.Formatter(fnm))

	return fnm, nil
}

func setTransitv4(c []config.Transitv4Config, m *ebpf.Map) (*srv6.TransitTablev4sMap, error) {
	tranv4 := srv6.MappingTransitTablev4(m)

	for _, t4 := range c {
		actId := srv6.Seg6EncapModeInt(t4.Action)
		if srv6.SEG6_IPTUNNEL_MAX == actId {
			return nil, errors.New(fmt.Sprintf("%v not found", t4.Action))
		}
		_, cidr, err := net.ParseCIDR(t4.Addr)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		prefixlen, _ := cidr.Mask.Size()

		sip := net.ParseIP(t4.SAddr)
		var convip [4]byte
		var startSip [16]byte
		copy(convip[:], cidr.IP.To16())
		if sip != nil {
			copy(startSip[:], sip.To16())
		}

		var newsegments [srv6.MAX_SEGMENTS][16]byte
		for i, seg := range t4.Segments {
			var segmentaddr [16]byte
			copy(segmentaddr[:], net.ParseIP(seg).To16())
			log.Println("segments addr", i, segmentaddr)

			newsegments[i] = segmentaddr
		}

		segLen := len(t4.Segments)
		if srv6.MAX_SEGMENTS < segLen {
			return nil, errors.New(fmt.Sprintf("Max Segments Entry over. %v/%v", len(newsegments), srv6.MAX_SEGMENTS))
		} else if segLen == 0 {
			return nil, errors.New(fmt.Sprintf("Length Entry empty. %v/%v", len(newsegments), srv6.MAX_SEGMENTS))
		}

		err = tranv4.Update(
			srv6.TransitTablev4{
				Action:         actId,
				Segment_length: uint32(segLen),
				Saddr:          startSip,
				Segments:       newsegments,
			},
			convip,
			uint32(prefixlen),
		)
		if err != nil {
			log.Printf("Unable to Insert into eBPF map: %v", err)
			return nil, errors.WithStack(err)
		}
	}
	fmt.Printf("%# v\n", pretty.Formatter(tranv4))

	return tranv4, nil
}
