// A command line tool for operating a certification authority.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica"
)

var flags = flag.NewFlagSet("lorica", flag.ExitOnError)
var opts struct {
	module   string
	label    string
	pin      string
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
	commands := map[string]func([]string){
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

	opts.module = os.Getenv("LORICA_TOKEN_MODULE")
	opts.label = os.Getenv("LORICA_TOKEN_LABEL")
	opts.pin = os.Getenv("LORICA_TOKEN_PIN")
	if opts.module == "" || opts.label == "" || opts.pin == "" {
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

	cmd(flags.Args())
}
