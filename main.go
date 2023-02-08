package main

import (
	"github.com/edgelesssys/go-tdx-qpl/verification"
	"log"
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
	log.Println(parsedQuote)

	return nil
}
