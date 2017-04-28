package main

import (
	"fmt"

	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica/cryptoki"
)

func infoCommand(tk *cryptoki.Token, args []string) {
	info, err := tk.Info()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token label:\t%s\n", info.Label)
	fmt.Printf("Manufacturer:\t%s\n", info.ManufacturerID)
	fmt.Printf("Token model:\t%s\n", info.Model)
	fmt.Printf("Serial number:\t%s\n", info.SerialNumber)
}
