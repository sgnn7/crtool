package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/sgnn7/crtool/pkg/cli"
)

func main() {
	err := cli.RunCRTool()
	if err != nil {
		log.Fatal(
			errors.New(fmt.Sprintf("ERROR: %s", err.Error())),
		)
	}
}
