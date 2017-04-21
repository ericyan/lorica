package main

import (
	"fmt"
	"os"

	"github.com/ericyan/lorica/cryptoki"
)

func infoCommand(tk *cryptoki.Token, args []string) {
	info, err := tk.Info()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Token label:\t%s\n", info.Label)
	fmt.Printf("Manufacturer:\t%s\n", info.ManufacturerID)
	fmt.Printf("Token model:\t%s\n", info.Model)
	fmt.Printf("Serial number:\t%s\n", info.SerialNumber)
}
