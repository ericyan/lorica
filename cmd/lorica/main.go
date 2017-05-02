// A command line tool for operating a certification authority.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica"
	"github.com/ericyan/lorica/cryptoki"
)

var flags = flag.NewFlagSet("lorica", flag.ExitOnError)
var opts struct {
	config   string
	ca       string
	selfsign bool
	verbose  bool
}
var cfg *lorica.Config

func init() {
	flags.StringVar(&opts.config, "config", "", "path to configuration file")
	flags.StringVar(&opts.ca, "ca", "", "certificate of the signing CA")
	flags.BoolVar(&opts.selfsign, "selfsign", false, "self-sign the CSR and output the signed certificate")
	flags.BoolVar(&opts.verbose, "v", false, "increase verbosity")
}

func main() {
	commands := map[string]func(*cryptoki.Token, []string){
		"info": infoCommand,
		"init": initCommand,
		"sign": signCommand,
	}

	if len(os.Args) < 2 {
		fmt.Printf("Usage:\n\tlorica command [-flags] arguments\n")
		os.Exit(2)
	}

	cmd, ok := commands[os.Args[1]]
	if !ok {
		fmt.Printf("invalid command: %s\n", os.Args[1])
		os.Exit(2)
	}

	module := os.Getenv("LORICA_TOKEN_MODULE")
	label := os.Getenv("LORICA_TOKEN_LABEL")
	pin := os.Getenv("LORICA_TOKEN_PIN")
	if module == "" || label == "" || pin == "" {
		fmt.Printf("missing token env\n")
		os.Exit(2)
	}

	flags.Parse(os.Args[2:])

	if opts.verbose {
		log.Level = log.LevelDebug
	} else {
		log.Level = log.LevelInfo
	}

	if opts.config != "" {
		var err error
		cfg, err = lorica.LoadConfigFile(opts.config)
		if err != nil {
			log.Fatal(err)
		}
	}

	// TODO: Should use read-only session for read-only operations
	token, err := cryptoki.OpenToken(module, label, pin, false)
	if err != nil {
		log.Fatal(err)
	}
	defer token.Close()

	cmd(token, flags.Args())
}
