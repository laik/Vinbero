package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
 	"syscall"
	"fmt"
//	"time"
	"net"

	"github.com/pkg/errors"
	"github.com/takehaya/srv6-gtp/version"
	"github.com/takehaya/srv6-gtp/xdptool"
	"github.com/takehaya/srv6-gtp/srv6"

	"gopkg.in/yaml.v2"
)

type FunctionsPram struct{
	Action string `yaml:"action,omitempty"`
	Addr string `yaml:"addr,omitempty"`
}

type Transitv4Pram struct{
	Action string `yaml:"action,omitempty"`
	Addr string `yaml:"addr,omitempty"`
	SAddr string `yaml:"action_source_addr,omitempty"`
	Segments []string `yaml:"segments,omitempty"`
}

type SetPram struct{
	Functions []FunctionsPram `yaml:"functions,omitempty"`
	Transitv4 []Transitv4Pram `yaml:"transitv4,omitempty"`
}

type Config struct {
	ElfFilepath string `yaml:"elffilepath,omitempty"`
	ProgName    string `yaml:"progname,omitempty"`
	Devices     []string `yaml:"devices,omitempty"`
	Set         SetPram `yaml:"set,omitempty"`
} 

func ConfigReadOnStruct(fileBuffer []byte) (Config, error) {
	data := Config{}
	err := yaml.Unmarshal(fileBuffer, &data)
	if err != nil {
		log.Println(errors.WithStack(err))
		return Config{}, errors.WithStack(err)
	}
	return data, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v", err)
	}
}

type ipAddressList []string


var iface = flag.String("iface", "eth0", "Interface to bind XDP program to")
var elf = flag.String("elf", "out/srv6.o", "clang/llvm compiled binary file")
var ipList = ipAddressList{"10.0.0.1"}

func run() error {
	configFile := flag.String("config-file", "sr.yml", "config file path")
	v := flag.Bool("v", false, "version")
	flag.Parse()

	if *v {
		log.Printf("version: %s.%s\n", version.Version, version.Revision)
		return nil
	}
	
	// config loading
	buf, err := ioutil.ReadFile(*configFile)
	if err != nil {
		return errors.WithStack(err)
	}

	data, err := ConfigReadOnStruct(buf)
	if err != nil {
		return errors.WithStack(err)
	}
	// init
	xdptool.PossibleCpuInit()

	coll, err := xdptool.LoadElf(data.ElfFilepath)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, dev := range data.Devices{
		// Attach to interface
		err = xdptool.Attach(coll, data.ProgName, dev)
		if err != nil {
			return errors.WithStack(err)
		}
		log.Println("attached device: %v", dev)
	}	

	// match map
	function_m, err := srv6.NewFunctionTable(coll)
	if err != nil {
		return errors.WithStack(err)
	}

	// transit v4 map
	v4table_m, err := srv6.NewTransitTablev4(coll)
	if err != nil {
		return errors.WithStack(err)
	}

	// txport map
	txp_m, err := srv6.NewTxPort(coll)
	if err != nil {
		return errors.WithStack(err)
	}


	// write to redirect map
	for _, dev := range data.Devices{
		iface, err := net.InterfaceByName(dev)
		if err != nil {
			log.Printf("fail to interface: %v", dev)
			return errors.WithStack(err)
		}
		err = txp_m.Update(srv6.TxPort{Iface: iface.Index}, iface.Index)
		if err != nil {
			log.Printf("Unable to Insert into eBPF map: %v", err)
			return errors.WithStack(err)
		}
	}
	
	// write to params map
	if funcs:= data.Set.Functions; 0 < len(funcs) {
		for _, fn := range funcs{
			action := fn.Action
			addr := fn.Addr
			fn_enum := srv6.SEG6LocalActionEnum(action)
			if srv6.SEG6_LOCAL_ACTION_MAX == fn_enum{
				return errors.New(fmt.Sprintf("%v not found", action))
			}
			if addr == ""{
				return errors.New(fmt.Sprintf("addr not found"))
			}

			// var big_convaddr [16]byte
			// var litle_convaddr [16]byte
			// copy(big_convaddr[:], net.ParseIP(addr).To16())
			// for index, bit := range big_convaddr{
			// 	litle_convaddr[16 - 1 - index] = bit
			// }
			
			var convip [16]byte
			copy(convip[:], net.ParseIP(addr).To16())
			fmt.Println(convip)
			err := function_m.Update(
				srv6.FunctionTable{Function: fn_enum}, 
				convip,
			)
			if err != nil {
				log.Printf("Unable to Insert into eBPF map: %v", err)
				return errors.WithStack(err)
			}
			log.Println("Insert into eBPF map seg6 action: %v", fn)
		}
	}
	if tranv4s := data.Set.Transitv4; 0 < len(tranv4s) {
		for _, tran := range tranv4s{
			action := tran.Action
			addr := tran.Addr
			saddr := tran.SAddr
			segments := tran.Segments

			encap_enum := srv6.SEG6EncapModeInt(action)
			log.Println("encap_enum", encap_enum)
			if srv6.SEG6_IPTUN_MODE_MAX == encap_enum{
				return errors.New(fmt.Sprintf("%v not found", action))
			}
			if addr == ""{
				return errors.New(fmt.Sprintf("addr not found"))
			}

			var newsegments [srv6.MAX_SEGMENTS][16]byte
			for i, seg := range segments{
				var segmentaddr [16]byte
				copy(segmentaddr[:], net.ParseIP(seg).To16())
				log.Println("segments addr", i, segmentaddr)

				newsegments[i] = segmentaddr
			}
			l := len(segments)
			log.Println("seg len", l)
			if srv6.MAX_SEGMENTS < l {
				return errors.New(fmt.Sprintf("Max Segments Entry over. %v/%v", len(newsegments), srv6.MAX_SEGMENTS))
			}
			var convSaddr [16]byte
			copy(convSaddr[:], net.ParseIP(saddr).To16())
			var convAddr [4]byte
			copy(convAddr[:], net.ParseIP(addr).To4())

			err := v4table_m.Update(
				srv6.TransitTablev4{
					Action: encap_enum,
					Segment_length: uint32(l),
					Saddr: convSaddr,
					Segments: newsegments,
					}, 
					convAddr,
			)
			if err != nil {
				log.Printf("Unable to Insert into eBPF map: %v", err)
				return errors.WithStack(err)
			}
		}
	}


	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)


	log.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	log.Println("Press CTRL+C to stop.")
	// Print stat every second / exit on CTRL+C
	// ticker := time.NewTicker(1 * time.Second)
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
			for _, dev := range data.Devices{
				// Attach to interface
				err = xdptool.Detach(dev)
				if err != nil {
					return errors.WithStack(err)
				}
				log.Println("attached device: %v", dev)
			}
			fmt.Println("\nDetaching program and exit")

			return nil
		}
	}
	
	return nil
}
