package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/ericyan/lorica"
	"github.com/ericyan/lorica/cryptoki"
)

func signCommand(tk *cryptoki.Token, args []string) {
	flags := flag.NewFlagSet("init", flag.ExitOnError)
	caFilename := flags.String("ca", "", "certificate of the signing CA")
	flags.Parse(args)

	caPEM, err := readFile(*caFilename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	caCert, err := helpers.ParseCertificatePEM(caPEM)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	key, err := cryptoki.FindKeyPair(tk, caCert.PublicKey)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	ca, err := lorica.NewCA(caCert, nil, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	csrFilename := flags.Arg(0)
	csrPEM, err := readFile(csrFilename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	certPEM, err := ca.Sign(csrPEM)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	certPEMFilename := strings.TrimSuffix(csrFilename, ".pem") + ".cert.pem"
	err = writeFile(certPEMFilename, certPEM)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
