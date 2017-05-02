package cmd

import (
	"errors"
	"io/ioutil"
	"os"
)

// ReadFile reads the file named by filename and returns the contents.
// It reads from stdin if the file is "-".
func ReadFile(filename string) ([]byte, error) {
	switch filename {
	case "":
		return nil, errors.New("missing filename")
	case "-":
		return ioutil.ReadAll(os.Stdin)
	default:
		return ioutil.ReadFile(filename)
	}
}

// WriteFile writes data to a file named by filename. If the file does
// not exist, WriteFile creates it with permissions 0644.
func WriteFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}
