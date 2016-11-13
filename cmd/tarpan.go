package main

import (
	"fmt"
	"os"

	"github.com/hichtakk/tarpan"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	debug  = kingpin.Flag("debug", "Set debug mode").Short('d').Bool()
	output = kingpin.Flag("output", "output type").Short('o').String()
	target = kingpin.Arg("target", "target json").Required().ExistingFile()
)

func main() {
	kingpin.Parse()
	if *debug == true {
		fmt.Printf("debug: %v, target: %s, output: %s\n", *debug, *target, *output)
	}
	exit, err := tarpan.Run(*target, *output, *debug)
	if err != nil {
		fmt.Println(err)
	}
	os.Exit(exit)
}
