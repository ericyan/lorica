// A command line tool for operating a certification authority.
package main

import (
	"fmt"
	"os"

	"github.com/cloudflare/cfssl/log"
	"github.com/ericyan/lorica/cryptoki"
)

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

	// TODO: Should use read-only session for read-only operations
	token, err := cryptoki.OpenToken(module, label, pin, false)
	if err != nil {
		log.Fatal(err)
	}
	defer token.Close()

	cmd(token, os.Args[2:])
}
