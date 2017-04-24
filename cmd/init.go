package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/cfssl/csr"
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
		fmt.Println(err)
		os.Exit(1)
	}

	req := csr.New()
	err = json.Unmarshal(csrJSON, req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	key, err := cryptoki.NewKeyPair(tk, req.CN, req.KeyRequest)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	csrPEM, err := csr.Generate(key, req)
	if err != nil {
		os.Exit(1)
	}

	if *selfsign {
		ca, err := lorica.NewCA(nil, nil, key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		certPEM, err := ca.Sign(csrPEM)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		certPEMFilename := strings.Replace(csrFilename, ".json", ".pem", 1)
		err = writeFile(certPEMFilename, certPEM)
	} else {
		csrPEMFilename := strings.Replace(csrFilename, ".json", ".csr.pem", 1)
		err = writeFile(csrPEMFilename, csrPEM)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
