// A command line tool for operating a certification authority.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica/internal/cliutil"
	"github.com/ericyan/lorica/pkg/ca"
	"github.com/ericyan/lorica/pkg/cryptoki"
	"github.com/joho/godotenv"
)

var flags = flag.NewFlagSet("lorica", flag.ExitOnError)
var opts struct {
	module  string
	label   string
	pin     string
	config  string
	ca      string
	verbose bool
}
var cfg *ca.Config

func init() {
	flags.StringVar(&opts.config, "config", "", "path to configuration file")
	flags.StringVar(&opts.ca, "ca", "", "database of the signing CA")
	flags.BoolVar(&opts.verbose, "v", false, "increase verbosity")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage:\n\tlorica command [-flags] arguments\n")
		os.Exit(2)
	}
	command := os.Args[1]

	flags.Parse(os.Args[2:])
	args := flags.Args()

	godotenv.Load()
	opts.module = os.Getenv("LORICA_TOKEN_MODULE")
	opts.label = os.Getenv("LORICA_TOKEN_LABEL")
	opts.pin = os.Getenv("LORICA_TOKEN_PIN")
	if opts.module == "" || opts.label == "" || opts.pin == "" {
		fmt.Printf("missing token env\n")
		os.Exit(2)
	}

	if opts.verbose {
		log.Level = log.LevelDebug
	} else {
		log.Level = log.LevelInfo
	}

	if opts.config != "" {
		log.Debugf("loading configuration file from %s", opts.config)
		config, err := ioutil.ReadFile(opts.config)
		if err != nil {
			log.Fatal(err)
		}

		cfg, err = ca.LoadConfig(config)
		if err != nil {
			log.Fatal(err)
		}
	}

	tk, err := cryptoki.OpenToken(opts.module, opts.label, opts.pin)
	if err != nil {
		log.Fatal(err)
	}
	defer tk.Close()

	switch command {
	case "info":
		info, err := tk.Info()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Token label:\t%s\n", info.Label)
		fmt.Printf("Manufacturer:\t%s\n", info.ManufacturerID)
		fmt.Printf("Token model:\t%s\n", info.Model)
		fmt.Printf("Serial number:\t%s\n", info.SerialNumber)
	case "init":
		ca, err := ca.Init(cfg, tk)
		if err != nil {
			log.Fatal(err)
		}

		var pem []byte
		var outputFilename string

		pem, err = ca.CertificatePEM()
		if err != nil {
			log.Error(err)
		}

		outputFilename = strings.Replace(opts.config, ".json", ".crt.pem", 1)

		if pem == nil {
			pem, err = ca.CertificateRequestPEM()
			if err != nil {
				log.Fatal(err)
			}
		}

		outputFilename = strings.Replace(opts.config, ".json", ".csr.pem", 1)

		err = cliutil.WriteFile(outputFilename, pem)
		if err != nil {
			log.Fatal(err)
		}
	case "sign":
		csrFilename := args[0]
		csrPEM, err := cliutil.ReadFile(csrFilename)
		if err != nil {
			log.Fatal(err)
		}

		ca, err := ca.Open(opts.ca, tk)
		if err != nil {
			log.Fatal(err)
		}

		certPEM, err := ca.Issue(csrPEM)
		if err != nil {
			log.Fatal(err)
		}

		certPEMFilename := strings.TrimSuffix(csrFilename, ".csr.pem") + ".crt.pem"
		err = cliutil.WriteFile(certPEMFilename, certPEM)
		if err != nil {
			log.Fatal(err)
		}
	case "revoke":
		ca, err := ca.Open(opts.ca, tk)
		if err != nil {
			log.Fatal(err)
		}

		keyID, err := ca.KeyID()
		if err != nil {
			log.Fatal(err)
		}

		err = ca.Revoke(args[0], string(keyID), 0)
		if err != nil {
			log.Fatal(err)
		}
	case "crl":
		ca, err := ca.Open(opts.ca, tk)
		if err != nil {
			log.Fatal(err)
		}

		crlDER, err := ca.CRL(30 * 24 * time.Hour)
		if err != nil {
			log.Fatal(err)
		}

		err = cliutil.WriteFile("crl.der", crlDER)
		if err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Printf("invalid command: %s\n", command)
		os.Exit(2)
	}
}
