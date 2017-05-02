package main

import (
	"encoding/json"
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica"
	"github.com/ericyan/lorica/cmd"
	"github.com/ericyan/lorica/cryptoki"
)

func initCommand(tk *cryptoki.Token, args []string) {
	csrFilename := args[0]
	csrJSON, err := cmd.ReadFile(csrFilename)
	if err != nil {
		log.Fatal(err)
	}

	req := csr.New()
	err = json.Unmarshal(csrJSON, req)
	if err != nil {
		log.Fatal(err)
	}

	key, err := cryptoki.NewKeyPair(tk, req.CN, req.KeyRequest)
	if err != nil {
		log.Fatal(err)
	}

	csrPEM, err := csr.Generate(key, req)
	if err != nil {
		log.Fatal(err)
	}

	if opts.selfsign {
		ca, err := lorica.NewCA(nil, cfg, key)
		if err != nil {
			log.Fatal(err)
		}

		certPEM, err := ca.Sign(csrPEM)
		if err != nil {
			log.Fatal(err)
		}

		certPEMFilename := strings.Replace(csrFilename, ".csr.json", ".crt.pem", 1)
		err = cmd.WriteFile(certPEMFilename, certPEM)
	} else {
		csrPEMFilename := strings.Replace(csrFilename, ".csr.json", ".csr.pem", 1)
		err = cmd.WriteFile(csrPEMFilename, csrPEM)
	}
	if err != nil {
		log.Fatal(err)
	}
}
