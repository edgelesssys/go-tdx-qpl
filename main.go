package main

import (
	"encoding/json"
	"fmt"
	"github.com/edgelesssys/go-tdx-qpl/verification"
	"os"
)

func main() {
	if err := parseBlob(); err != nil {
		panic(err)
	}
}

func parseBlob() error {
	rawQuote, err := os.ReadFile("blobs/quote")
	if err != nil {
		return err
	}

	parsedQuote, err := verification.ParseQuote(rawQuote)
	if err != nil {
		return err
	}

	prettyPrint, err := json.MarshalIndent(parsedQuote, "", " ")
	if err != nil {
		return err
	}

	fmt.Println(string(prettyPrint))

	return nil
}
