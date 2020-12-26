package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-gtp/gtpv1"
)

func client(listen, peer, subscriber, ote, ite string) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:2152", listen))
	if err != nil {
		return errors.WithStack(err)
	}
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("$v:2152", peer))
	if err != nil {
		return errors.WithStack(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uConn, err := gtpv1.DialUPlane(ctx, addr, raddr)
	defer uConn.Close()

	if err := uConn.EnableKernelGTP("gtp0", gtpv1.RoleSGSN); err != nil {
		return errors.WithStack(err)
	}
	oteint, err := strconv.Atoi(ote)
	if err != nil {
		return errors.WithStack(err)
	}
	iteint, err := strconv.Atoi(ite)
	if err != nil {
		return errors.WithStack(err)
	}

	if err = uConn.AddTunnelOverride(
		net.ParseIP(peer),       // GTP peer's IP
		net.ParseIP(subscriber), // subscriber's IP
		uint32(oteint),          // outgoing TEID
		uint32(iteint),          // incoming TEID
	); err != nil {
		return errors.WithStack(err)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		select {
		case <-signalChan:
			fmt.Println("Ctl-C exit")
			// delete a tunnel by giving an incoming TEID.
			if err = uConn.DelTunnelByITEI(uint32(iteint)); err != nil {
				return errors.WithStack(err)
			}

			// delete a tunnel by giving an IP address assigned to a subscriber.
			if err = uConn.DelTunnelByMSAddress(net.ParseIP(subscriber)); err != nil {
				return errors.WithStack(err)
			}
			return nil
		}
	}
	return nil
}
