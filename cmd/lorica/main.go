// Package main implements a command-line tool, lorica, for operating a
// certification authority.
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica/internal/cliutil"
	"github.com/ericyan/lorica/pkg/ca"
	"github.com/ericyan/lorica/pkg/cryptoki"
	"github.com/joho/godotenv"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app     = kingpin.New("lorica", "A command-line tool for operating a certification authority.")
	caFile  = app.Flag("ca-file", "path to CA database").Default("lorica.ca").Short('f').String()
	verbose = app.Flag("verbose", "increase verbosity").Short('v').Bool()

	infoCmd = app.Command("info", "Show infomation about the PKCS #11 token.")

	initCmd  = app.Command("init", "Initialize a certification authority.")
	initCfg  = initCmd.Arg("config", "path to configuration file").Required().String()
	initCSR  = initCmd.Flag("export-csr", "export CA CSR to file").PlaceHolder("FILE").String()
	initCert = initCmd.Flag("export-cert", "export CA certificate to file").PlaceHolder("FILE").String()

	certCmd    = app.Command("cert", "Export/import the CA certificate.")
	certFile   = certCmd.Arg("file", "filename for CRL").Default("/dev/stdout").String()
	certImport = certCmd.Flag("import", "import the CA certificate from <file>").Bool()

	issueCmd  = app.Command("issue", "Issue a certificate.")
	issueCSR  = issueCmd.Arg("csr", "path to CSR file (must be PEM-encoded)").Required().String()
	issueCert = issueCmd.Flag("export-cert", "export issued certificate to file").PlaceHolder("FILE").String()

	revokeCmd    = app.Command("revoke", "Revoke a certificate.")
	revokeSerial = revokeCmd.Arg("serial", "serial number of the certificate to be revoked").Required().String()
	revokeReason = revokeCmd.Arg("reason", "RFC 5280 reason code for revocation").Default("0").Int()

	crlCmd  = app.Command("crl", "Generate a new Certificate Revocation List.")
	crlFile = crlCmd.Arg("file", "output filename for CRL").Required().String()
	crlTTL  = crlCmd.Flag("ttl", "number of days after which the CRL will expire").Default("30").Int()
)

func main() {
	app.HelpFlag.Short('h')
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	if *verbose {
		log.Level = log.LevelDebug
	} else {
		log.Level = log.LevelInfo
	}

	godotenv.Load()
	tk, err := cryptoki.OpenToken(os.Getenv("LORICA_TOKEN_MODULE"), os.Getenv("LORICA_TOKEN_LABEL"), os.Getenv("LORICA_TOKEN_PIN"))
	if err != nil {
		log.Fatal(err)
	}
	defer tk.Close()

	switch command {
	case infoCmd.FullCommand():
		info, err := tk.Info()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Token label:\t%s\n", info.Label)
		fmt.Printf("Manufacturer:\t%s\n", info.ManufacturerID)
		fmt.Printf("Token model:\t%s\n", info.Model)
		fmt.Printf("Serial number:\t%s\n", info.SerialNumber)
	case initCmd.FullCommand():
		config, err := ioutil.ReadFile(*initCfg)
		if err != nil {
			log.Fatal(err)
		}
		cfg, err := ca.LoadConfig(config)
		if err != nil {
			log.Fatal(err)
		}

		ca, err := ca.Init(cfg, *caFile, tk)
		if err != nil {
			log.Fatal(err)
		}

		if *initCSR != "" {
			csr, err := ca.CertificateRequestPEM()
			if err != nil {
				log.Fatal(err)
			}

			err = cliutil.WriteFile(*initCSR, csr)
			if err != nil {
				log.Fatal(err)
			}
		}

		if *initCert != "" {
			if !cfg.SelfSign {
				log.Fatal("certificate available for self-signed CA only")
			}

			cert, err := ca.CertificatePEM()
			if err != nil {
				log.Error(err)
			}

			err = cliutil.WriteFile(*initCert, cert)
			if err != nil {
				log.Fatal(err)
			}
		}
	case certCmd.FullCommand():
		ca, err := ca.Open(*caFile, tk)
		if err != nil {
			log.Fatal(err)
		}

		if *certImport {
			certPEM, err := cliutil.ReadFile(*certFile)
			if err != nil {
				log.Fatal(err)
			}

			err = ca.ImportCertificate(certPEM)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			certPEM, err := ca.CertificatePEM()
			if err != nil {
				log.Fatal(err)
			}
			err = cliutil.WriteFile(*certFile, certPEM)
			if err != nil {
				log.Fatal(err)
			}
		}
	case issueCmd.FullCommand():
		csrPEM, err := cliutil.ReadFile(*issueCSR)
		if err != nil {
			log.Fatal(err)
		}

		ca, err := ca.Open(*caFile, tk)
		if err != nil {
			log.Fatal(err)
		}

		certPEM, err := ca.Issue(csrPEM)
		if err != nil {
			log.Fatal(err)
		}

		if *issueCert != "" {
			err = cliutil.WriteFile(*issueCert, certPEM)
			if err != nil {
				log.Fatal(err)
			}
		}
	case revokeCmd.FullCommand():
		ca, err := ca.Open(*caFile, tk)
		if err != nil {
			log.Fatal(err)
		}

		err = ca.Revoke(*revokeSerial, *revokeReason)
		if err != nil {
			log.Fatal(err)
		}
	case crlCmd.FullCommand():
		ca, err := ca.Open(*caFile, tk)
		if err != nil {
			log.Fatal(err)
		}

		crlDER, err := ca.CRL(time.Duration(*crlTTL) * 24 * time.Hour)
		if err != nil {
			log.Fatal(err)
		}

		err = cliutil.WriteFile(*crlFile, crlDER)
		if err != nil {
			log.Fatal(err)
		}
	}
}
