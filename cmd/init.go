package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
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

	csr := csr.New()
	err = json.Unmarshal(csrJSON, csr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	key, err := cryptoki.NewKeyPair(tk, csr.CN, csr.KeyRequest)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	certPEM, csrPEM, err := initca.NewFromSigner(csr, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if *selfsign {
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
