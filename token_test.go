package lorica

import (
	"fmt"
	"os"
)

// ExampleToken demonstrates how to work with a token.
//
// It expects a SoftHSM2 token labeled lorica_test present and the token
// should be initialized with user PIN 123456.
func ExampleToken() {
	token, err := OpenToken("/usr/lib/softhsm/libsofthsm2.so", "lorica_test", "123456")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer token.Close()

	info, err := token.Info()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(info.Label)
	fmt.Println(info.Model)

	// Output:
	// lorica_test
	// SoftHSM v2
}
