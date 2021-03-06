package cli

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

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

func HandleOutput(output string, options ssl.Options) error {
	if options.Debug {
		log.Println("Handling action output...")
	}

	if options.OutputFile != "" {
		if options.Debug {
			log.Println("Writing to file:")
			log.Println(output)
		}

		return ioutil.WriteFile(options.OutputFile, []byte(output), 0640)
	}

	fmt.Printf(output)
	return nil
}

func RunCRTool() error {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	var certEncoding,
		outputFile,
		port,
		target string
	var debug bool

	dumpCommand := flag.NewFlagSet("dump", flag.ExitOnError)
	verifyCommand := flag.NewFlagSet("verify", flag.ExitOnError)

	// Dump flags
	dumpCommand.StringVar(&target, "target", targetDefaultValue, targetUsage)
	dumpCommand.StringVar(&target, "t", targetDefaultValue, targetUsage+" (shorthand)")

	dumpCommand.StringVar(&port, "port", portDefaultValue, portUsage)
	dumpCommand.StringVar(&port, "p", portDefaultValue, portUsage+" (shorthand)")

	dumpCommand.StringVar(&outputFile, "output", outputFileDefaultValue, outputFileUsage)
	dumpCommand.StringVar(&outputFile, "o", outputFileDefaultValue, outputFileUsage+" (shorthand)")

	dumpCommand.StringVar(&certEncoding, "encoding", encodingDefaultValue, encodingUsage)
	dumpCommand.StringVar(&certEncoding, "e", encodingDefaultValue, encodingUsage+" (shorthand)")

	dumpCommand.BoolVar(&debug, "debug", debugDefaultValue, debugUsage)

	// Verify flags
	verifyCommand.StringVar(&target, "target", targetDefaultValue, targetUsage)
	verifyCommand.StringVar(&target, "t", targetDefaultValue, targetUsage+" (shorthand)")

	verifyCommand.StringVar(&port, "port", portDefaultValue, portUsage)
	verifyCommand.StringVar(&port, "p", portDefaultValue, portUsage+" (shorthand)")

	verifyCommand.StringVar(&outputFile, "output", outputFileDefaultValue, outputFileUsage)
	verifyCommand.StringVar(&outputFile, "o", outputFileDefaultValue, outputFileUsage+" (shorthand)")

	verifyCommand.BoolVar(&debug, "debug", debugDefaultValue, debugUsage)

	if len(os.Args) < 2 {
		showVersion := flag.Bool("v", false, versionUsage)

		flag.Parse()

		if *showVersion {
			fmt.Printf("%s v%s\n", path.Base(os.Args[0]), version.FullVersionName)
			return nil
		}

		fmt.Println("verify or dump subcommand is required")
		os.Exit(1)
	}

	if debug {
		log.Println("Starting...")
	}

	switch action := os.Args[1]; action {
	case "dump":
		dumpCommand.Parse(os.Args[2:])
		options := ssl.Options{
			Debug:      debug,
			OutputFile: outputFile,
		}

		encodingType, err := encoding.NewTypeFromStr(certEncoding)
		if err != nil {
			return err
		}

		output, err := ssl.GetServerCert(target, port, encodingType, options)
		if err != nil {
			return err
		}

		return HandleOutput(output, options)
	case "verify":
		verifyCommand.Parse(os.Args[2:])
		options := ssl.Options{
			Debug:      debug,
			OutputFile: outputFile,
		}

		output, err := ssl.VerifyServerCertChain(target, port, options)
		if err != nil {
			return err
		}

		return HandleOutput(output, options)
	default:
		flag.PrintDefaults()
		return errors.New(fmt.Sprintf("action '%s' not supported - only 'dump' and 'verify' are supported",
			action))
	}

	return nil
}
