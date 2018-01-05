package main

import (
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica/cmd"
	"github.com/ericyan/lorica/cryptoki"
	"github.com/ericyan/lorica/internal/procedure"
)

func signCommand(args []string) {
	tk, err := cryptoki.OpenToken(opts.module, opts.label, opts.pin, true)
	if err != nil {
		log.Fatal(err)
	}
	defer tk.Close()

	caPEM, err := cmd.ReadFile(opts.ca)
	if err != nil {
		log.Fatal(err)
	}

	csrFilename := args[0]
	csrPEM, err := cmd.ReadFile(csrFilename)
	if err != nil {
		log.Fatal(err)
	}

	certPEM, err := procedure.Sign(tk, cfg, caPEM, csrPEM)
	if err != nil {
		log.Fatal(err)
	}

	certPEMFilename := strings.TrimSuffix(csrFilename, ".csr.pem") + ".crt.pem"
	err = cmd.WriteFile(certPEMFilename, certPEM)
	if err != nil {
		log.Fatal(err)
	}
}
