package main

import (
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica/cmd"
	"github.com/ericyan/lorica/cryptoki"
	"github.com/ericyan/lorica/internal/procedure"
)

func initCommand(args []string) {
	tk, err := cryptoki.OpenToken(opts.module, opts.label, opts.pin, false)
	if err != nil {
		log.Fatal(err)
	}
	defer tk.Close()

	pem, err := procedure.Init(tk, cfg, opts.selfsign)
	if err != nil {
		log.Fatal(err)
	}

	var outputFilename string
	if opts.selfsign {
		outputFilename = strings.Replace(opts.config, ".json", ".crt.pem", 1)
	} else {
		outputFilename = strings.Replace(opts.config, ".json", ".csr.pem", 1)
	}
	err = cmd.WriteFile(outputFilename, pem)
	if err != nil {
		log.Fatal(err)
	}
}
