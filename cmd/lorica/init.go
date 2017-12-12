package main

import (
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica/cmd"
	"github.com/ericyan/lorica/cryptoki"
	"github.com/ericyan/lorica/internal/ca"
)

func initCommand(args []string) {
	tk, err := cryptoki.OpenToken(opts.module, opts.label, opts.pin, false)
	if err != nil {
		log.Fatal(err)
	}
	defer tk.Close()

	req := cfg.CertificateRequest()
	key, err := cryptoki.NewKeyPair(tk, req.CN, req.KeyRequest)
	if err != nil {
		log.Fatal(err)
	}

	csrPEM, err := csr.Generate(key, req)
	if err != nil {
		log.Fatal(err)
	}

	if opts.selfsign {
		ca, err := ca.New(nil, cfg, key)
		if err != nil {
			log.Fatal(err)
		}

		certPEM, err := ca.Sign(csrPEM)
		if err != nil {
			log.Fatal(err)
		}

		certPEMFilename := strings.Replace(opts.config, ".json", ".crt.pem", 1)
		err = cmd.WriteFile(certPEMFilename, certPEM)
	} else {
		csrPEMFilename := strings.Replace(opts.config, ".json", ".csr.pem", 1)
		err = cmd.WriteFile(csrPEMFilename, csrPEM)
	}
	if err != nil {
		log.Fatal(err)
	}
}
