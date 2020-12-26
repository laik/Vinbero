package main

import (
	"fmt"
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/takehaya/vinbero/pkg/version"
	"github.com/urfave/cli"
)

func main() {
	app := newApp(version.Version)
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}

func newApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "gtptools"
	app.Version = version

	app.Usage = "Implementation to spit out only gtpv1-u"

	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "mode",
			Value: "server",
			Usage: "mode",
		},
		cli.StringFlag{
			Name:  "listen",
			Value: "172.0.1.1",
			Usage: "service listen addr",
		},
		cli.StringFlag{
			Name:  "peer",
			Value: "172.0.2.1",
			Usage: "remote peer addr",
		},
		cli.StringFlag{
			Name:  "subscriber",
			Value: "1.0.1.2",
			Usage: "mobile station addr",
		},
		cli.StringFlag{
			Name:  "ote",
			Value: "100",
			Usage: "putput TEID",
		},
		cli.StringFlag{
			Name:  "ite",
			Value: "200",
			Usage: "input TEID",
		},
	}
	app.Action = run
	return app
}

func run(ctx *cli.Context) (err error) {
	mode := ctx.String("mode")
	peer := ctx.String("peer")
	subscriber := ctx.String("subscriber")
	ote := ctx.String("ote")
	ite := ctx.String("ite")
	listen := ctx.String("listen")

	if mode == "server" {
		err = server(listen, peer, subscriber, ote, ite)

	} else if mode == "client" {
		err = client(listen, peer, subscriber, ote, ite)
	} else {
		return errors.Errorf("%v is inv mode", mode)
	}
	if err != nil {
		return err
	}
	fmt.Println("exit")
	return nil
}
