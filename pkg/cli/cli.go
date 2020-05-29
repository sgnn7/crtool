package cli

import (
	"fmt"
	"io/ioutil"
	"log"
)

type Options struct {
	Debug      bool
	OutputFile string
}

func (options *Options) HandleOutput(output string) error {
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
