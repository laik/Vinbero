package main

import (
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/takehaya/vinbero/internal"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/utils"
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
	app.Name = "Vinbero"
	app.Version = version

	app.Usage = "Vinbero in SRv6 Function Subset"

	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "configfile",
			Value: "./vinbero.yml",
			Usage: "config file path",
		},
	}
	app.Action = run
	return app
}

func run(ctx *cli.Context) error {
	configfile := ctx.String("configfile")

	if !utils.FileExists(configfile) {
		log.Fatalf("configfile file not found: %s\nHave you run 'make'?", configfile)
	}
	c, err := config.LoadFile(configfile)
	if err != nil {
		return errors.WithStack(err)
	}

	err = internal.App(c)
	if err != nil {
		return err
	}

	return nil
}
