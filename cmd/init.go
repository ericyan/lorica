package main

import (
	"encoding/json"
	"flag"
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica"
	"github.com/ericyan/lorica/cryptoki"
)

func initCommand(tk *cryptoki.Token, args []string) {
	flags := flag.NewFlagSet("init", flag.ExitOnError)
	selfsign := flags.Bool("selfsign", false, "self-sign the CSR and output the signed certificate")
	flags.Parse(args)

	csrFilename := flags.Arg(0)
	csrJSON, err := readFile(csrFilename)
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

	if *selfsign {
		ca, err := lorica.NewCA(nil, nil, key)
		if err != nil {
			log.Fatal(err)
		}

		certPEM, err := ca.Sign(csrPEM)
		if err != nil {
			log.Fatal(err)
		}

		certPEMFilename := strings.Replace(csrFilename, ".json", ".pem", 1)
		err = writeFile(certPEMFilename, certPEM)
	} else {
		csrPEMFilename := strings.Replace(csrFilename, ".json", ".csr.pem", 1)
		err = writeFile(csrPEMFilename, csrPEM)
	}
	if err != nil {
		log.Fatal(err)
	}
}
