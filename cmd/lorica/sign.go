package main

import (
	"strings"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica/cmd"
	"github.com/ericyan/lorica/cryptoki"
	"github.com/ericyan/lorica/internal/ca"
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
	caCert, err := helpers.ParseCertificatePEM(caPEM)
	if err != nil {
		log.Fatal(err)
	}

	key, err := cryptoki.FindKeyPair(tk, caCert.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	ca, err := ca.New(caCert, cfg, key)
	if err != nil {
		log.Fatal(err)
	}

	csrFilename := args[0]
	csrPEM, err := cmd.ReadFile(csrFilename)
	if err != nil {
		log.Fatal(err)
	}

	certPEM, err := ca.Sign(csrPEM)
	if err != nil {
		log.Fatal(err)
	}

	certPEMFilename := strings.TrimSuffix(csrFilename, ".csr.pem") + ".crt.pem"
	err = cmd.WriteFile(certPEMFilename, certPEM)
	if err != nil {
		log.Fatal(err)
	}
}
