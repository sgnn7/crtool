package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/sgnn7/crtool/pkg/certificates"
	"github.com/sgnn7/crtool/pkg/ssl"
)

const (
	targetDefaultValue = ""
	targetUsage        = "Destination IP or DNS name of the target"
	portDefaultValue   = "443"
	portUsage          = "Destination port"
	debugDefaultValue  = false
	debugUsage         = "Enables debug messages"
)

func exitWithError(message string) {
	log.Fatal(errors.New(fmt.Sprintf("ERROR: %s", message)))
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	var target string
	flag.StringVar(&target, "target", targetDefaultValue, targetUsage)
	flag.StringVar(&target, "t", targetDefaultValue, targetUsage+" (shorthand)")

	var port string
	flag.StringVar(&port, "port", portDefaultValue, portUsage)
	flag.StringVar(&port, "p", portDefaultValue, portUsage+" (shorthand)")

	debug := flag.Bool("debug", debugDefaultValue, debugUsage)
	flag.Parse()

	if *debug {
		log.Println("Starting...")
	}

	args := flag.Args()
	if len(args) < 1 {
		flag.PrintDefaults()
		exitWithError("action not specified")
	}

	switch action := args[0]; action {
	case "dump":
		err := ssl.GetServerCertificate(target, port, certificates.CertTypePEM)
		if err != nil {
			exitWithError(err.Error())
		}
		return
	default:
		flag.PrintDefaults()
		exitWithError(fmt.Sprintf("action '%s' not supported - only 'dump' is supported", action))
	}

}
