package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/sgnn7/crtool/pkg/cli"
	"github.com/sgnn7/crtool/pkg/encoding"
	"github.com/sgnn7/crtool/pkg/ssl"
	"github.com/sgnn7/crtool/pkg/version"
)

const (
	debugDefaultValue      = false
	debugUsage             = "Enables debug messages"
	encodingDefaultValue   = "pem"
	encodingUsage          = "Select type of output encoding ('pem' or 'der')"
	outputFileDefaultValue = ""
	outputFileUsage        = "Output destination path (defaults to stdout if not specified)"
	portDefaultValue       = "443"
	portUsage              = "Destination port"
	targetDefaultValue     = ""
	targetUsage            = "Destination IP or DNS name of the target"
	versionUsage           = "Show program version"
)

func exitWithError(message string) {
	log.Fatal(errors.New(fmt.Sprintf("ERROR: %s", message)))
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	var certEncoding,
		outputFile,
		port,
		target string

	flag.StringVar(&target, "target", targetDefaultValue, targetUsage)
	flag.StringVar(&target, "t", targetDefaultValue, targetUsage+" (shorthand)")

	flag.StringVar(&port, "port", portDefaultValue, portUsage)
	flag.StringVar(&port, "p", portDefaultValue, portUsage+" (shorthand)")

	flag.StringVar(&outputFile, "output", outputFileDefaultValue, outputFileDefaultValue)
	flag.StringVar(&outputFile, "o", outputFileDefaultValue, outputFileDefaultValue+" (shorthand)")

	flag.StringVar(&certEncoding, "encoding", encodingDefaultValue, encodingUsage)
	flag.StringVar(&certEncoding, "e", encodingDefaultValue, encodingUsage+" (shorthand)")

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

	encodingType, err := encoding.NewTypeFromStr(certEncoding)
	if err != nil {
		exitWithError(err.Error())
	}

	args := flag.Args()
	if len(args) < 1 {
		flag.PrintDefaults()
		exitWithError("action not specified")
	}

	cliOptions := cli.Options{
		Debug:      *debug,
		Encoding:   encodingType,
		OutputFile: outputFile,
	}

	switch action := args[0]; action {
	case "dump":
		err := ssl.GetServerCertificate(target, port, cliOptions.Encoding, cliOptions)
		if err != nil {
			exitWithError(err.Error())
		}
		return
	default:
		flag.PrintDefaults()
		exitWithError(fmt.Sprintf("action '%s' not supported - only 'dump' is supported", action))
	}
}
