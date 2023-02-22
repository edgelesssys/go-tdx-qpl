package main

import (
	"context"
	"fmt"
	"os"

	"github.com/edgelesssys/go-tdx-qpl/blobs"
	"github.com/edgelesssys/go-tdx-qpl/verification"
)

func main() {
	if err := testVerify(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func testVerify() error {
	verifier := verification.New()
	_, err := verifier.Verify(context.Background(), blobs.TDXQuote())
	return err
}
