package main

import (
	"os"

	"github.com/codegangsta/cli"
	"github.com/hichtakk/tarpan"
)

func main() {
	app := cli.NewApp()
	app.Name = "Tarpan"
	app.Usage = "SNMP Manager"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name: "target, t",
			//Value: "./target.json",
			Usage: "SNMP targets file",
		},
		cli.StringFlag{
			Name:   "debug, d",
			Usage:  "debug option",
			EnvVar: "TARPAN_DEBUG",
		},
	}
	app.Action = func(c *cli.Context) {
		if c.String("target") == "" {
			println("target file not found")
		} else {
			tarpan.Run(c.String("target"))
		}

		return
	}

	app.Run(os.Args)
}
