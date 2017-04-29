package main

import (
	"flag"
	"strings"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica"
	"github.com/ericyan/lorica/cryptoki"
)

func signCommand(tk *cryptoki.Token, args []string) {
	flags := flag.NewFlagSet("init", flag.ExitOnError)
	caFilename := flags.String("ca", "", "certificate of the signing CA")
	config := flags.String("config", "", "path to configuration file")
	verbose := flags.Bool("v", false, "increase verbosity")
	flags.Parse(args)

	if *verbose {
		log.Level = log.LevelDebug
	} else {
		log.Level = log.LevelInfo
	}

	var cfg *lorica.Config
	if *config != "" {
		var err error
		cfg, err = lorica.LoadConfigFile(*config)
		if err != nil {
			log.Fatal(err)
		}
	}

	caPEM, err := readFile(*caFilename)
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

	ca, err := lorica.NewCA(caCert, cfg, key)
	if err != nil {
		log.Fatal(err)
	}

	csrFilename := flags.Arg(0)
	csrPEM, err := readFile(csrFilename)
	if err != nil {
		log.Fatal(err)
	}

	certPEM, err := ca.Sign(csrPEM)
	if err != nil {
		log.Fatal(err)
	}

	certPEMFilename := strings.TrimSuffix(csrFilename, ".csr.pem") + ".crt.pem"
	err = writeFile(certPEMFilename, certPEM)
	if err != nil {
		log.Fatal(err)
	}
}
