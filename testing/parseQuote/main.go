package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/edgelesssys/go-tdx-qpl/verification/types"
)

func main() {
	if err := parseBlob(); err != nil {
		panic(err)
	}
}

func parseBlob() error {
	rawQuote, err := os.ReadFile("../../blobs/quote")
	if err != nil {
		return err
	}

	parsedQuote, err := types.ParseQuote(rawQuote)
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
