package main

import (
	"encoding/json"
	"flag"
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica"
	"github.com/ericyan/lorica/cmd"
	"github.com/ericyan/lorica/cryptoki"
)

func initCommand(tk *cryptoki.Token, args []string) {
	flags := flag.NewFlagSet("init", flag.ExitOnError)
	selfsign := flags.Bool("selfsign", false, "self-sign the CSR and output the signed certificate")
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

	csrFilename := flags.Arg(0)
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

	if *selfsign {
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
