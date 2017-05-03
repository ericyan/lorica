package main

import (
	"fmt"

	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica/cryptoki"
)

func infoCommand(args []string) {
	tk, err := cryptoki.OpenToken(opts.module, opts.label, opts.pin, true)
	if err != nil {
		log.Fatal(err)
	}
	defer tk.Close()

	info, err := tk.Info()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token label:\t%s\n", info.Label)
	fmt.Printf("Manufacturer:\t%s\n", info.ManufacturerID)
	fmt.Printf("Token model:\t%s\n", info.Model)
	fmt.Printf("Serial number:\t%s\n", info.SerialNumber)
}
