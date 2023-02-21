package main

import (
	"encoding/json"
	"fmt"

	"github.com/edgelesssys/go-tdx-qpl/blobs"
	"github.com/edgelesssys/go-tdx-qpl/verification/types"
)

func main() {
	if err := parseBlob(); err != nil {
		panic(err)
	}
}

func parseBlob() error {
	parsedQuote, err := types.ParseQuote(blobs.TDXQuote())
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
