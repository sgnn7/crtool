package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/sgnn7/crtool/pkg/certificates"
	"github.com/sgnn7/crtool/pkg/cli"
	"github.com/sgnn7/crtool/pkg/ssl"
	"github.com/sgnn7/crtool/pkg/version"
)

const (
	targetDefaultValue = ""
	targetUsage        = "Destination IP or DNS name of the target"
	portDefaultValue   = "443"
	portUsage          = "Destination port"
	debugDefaultValue  = false
	debugUsage         = "Enables debug messages"
	versionUsage       = "Show program version"
)

func exitWithError(message string) {
	log.Fatal(errors.New(fmt.Sprintf("ERROR: %s", message)))
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	var target, port string

	flag.StringVar(&target, "target", targetDefaultValue, targetUsage)
	flag.StringVar(&target, "t", targetDefaultValue, targetUsage+" (shorthand)")

	flag.StringVar(&port, "port", portDefaultValue, portUsage)
	flag.StringVar(&port, "p", portDefaultValue, portUsage+" (shorthand)")

	debug := flag.Bool("debug", debugDefaultValue, debugUsage)
	showVersion := flag.Bool("v", false, versionUsage)

	flag.Parse()

	if *showVersion {
		fmt.Printf("%s v%s\n", path.Base(os.Args[0]), version.FullVersionName)
		return
	}

	if *debug {
		log.Println("Starting...")
	}

	args := flag.Args()
	if len(args) < 1 {
		flag.PrintDefaults()
		exitWithError("action not specified")
	}

	cliOptions := cli.Options{
		Debug: *debug,
	}

	switch action := args[0]; action {
	case "dump":
		err := ssl.GetServerCertificate(target, port, certificates.CertTypePEM, cliOptions)
		if err != nil {
			exitWithError(err.Error())
		}
		return
	default:
		flag.PrintDefaults()
		exitWithError(fmt.Sprintf("action '%s' not supported - only 'dump' is supported", action))
	}
}
