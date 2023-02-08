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

	parsedQuote := verification.ParseQuote(rawQuote)
	signature := verification.ParseSignature(parsedQuote.Signature)

	prettyPrint, err := json.MarshalIndent(signature, "", " ")
	if err != nil {
		return err
	}

	fmt.Println(string(prettyPrint))

	return nil
}
