package internal

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kr/pretty"
	"github.com/pkg/errors"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/coreelf"
	"github.com/takehaya/vinbero/pkg/srv6"
	"github.com/takehaya/vinbero/pkg/xdptool"
)

func App(c *config.Config) error {
	obj, err := coreelf.ReadCollection()
	if err != nil {
		return errors.WithStack(err)
	}

	for _, dev := range c.InternalConfig.Devices {
		err = xdptool.Attach(obj.ProgramSrv6Handler, dev)
		if err != nil {
			return errors.WithStack(err)
		}
		fmt.Println("attached device: ", dev)
	}

	//xdpcap
	xdpcapHook := obj.MapXdpcapHook
	path := "/sys/fs/bpf/xdpcap_hook"
	os.RemoveAll(path)
	err = xdpcapHook.Pin(path)
	if err != nil {
		_ = disposeDevice(&c.InternalConfig)
		return errors.WithStack(err)
	}

	//addrheep
	os.RemoveAll(srv6.V6addrHeepPath)
	v6heep, err := setV6addrHeep(obj.MapInTapleV6Addr)
	if err != nil {
		return errors.WithStack(err)
	}
	fmt.Printf("%# v\n", pretty.Formatter(v6heep))

	//txport
	txm, err := setTxportDevice(&c.InternalConfig, obj.MapTxPort)
	if err != nil {
		_ = disposeDevice(&c.InternalConfig)
		return errors.WithStack(err)
	}
	fmt.Printf("%# v\n", pretty.Formatter(txm))

	//function map
	var srfn *srv6.FunctionTablesMap
	if funcs := c.Setting.Functions; 0 < len(funcs) {
		srfn, err = setSrv6Function(funcs, obj.MapFunctionTable)
		if err != nil {
			_ = disposeDevice(&c.InternalConfig)
			return errors.WithStack(err)
		}
	}
	fmt.Printf("%# v\n", pretty.Formatter(srfn))

	// tran v4
	var tran4 *srv6.TransitTablev4sMap
	if t4c := c.Setting.Transitv4; 0 < len(t4c) {
		tran4, err = setTransitv4(t4c, obj.MapTransitTableV4)
		if err != nil {
			_ = disposeDevice(&c.InternalConfig)
			return errors.WithStack(err)
		}
	}
	fmt.Printf("%# v\n", pretty.Formatter(tran4))

	// tran v6
	var tran6 *srv6.TransitTablev6sMap
	if t6c := c.Setting.Transitv6; 0 < len(t6c) {
		tran6, err = setTransitv6(t6c, obj.MapTransitTableV6)
		if err != nil {
			_ = disposeDevice(&c.InternalConfig)
			return errors.WithStack(err)
		}
	}
	fmt.Printf("%# v\n", pretty.Formatter(tran6))

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	fmt.Println("XDP program successfully loaded and attached.")
	fmt.Println("Press CTRL+C to stop.")
	for {
		select {
		case <-signalChan:
			// TODO: change prepare priority elf->ebpfmap make -> xdp attach
			err := disposeDevice(&c.InternalConfig)
			if err != nil {
				return errors.WithStack(err)
			}
			return nil
		}
	}
}

func disposeDevice(c *config.InternalConfig) error {
	for _, dev := range c.Devices {
		// Attach to interface
		err := xdptool.Detach(dev)
		if err != nil {
			return errors.WithStack(err)
		}
		fmt.Println("attached device: ", dev)
	}
	return nil
}
