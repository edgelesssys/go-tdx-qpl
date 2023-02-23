package main

import (
	"fmt"
	"log"
	"os"

	"github.com/edgelesssys/go-tdx-qpl/tdx"
)

func main() {
	if err := testTDX(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func testTDX() error {
	handle, err := tdx.Open()
	if err != nil {
		return err
	}
	defer handle.Close()

	extendData := "This machine is not backdoored :)"
	if err := tdx.ExtendRTMR(handle, []byte(extendData), 2); err != nil {
		return err
	}

	reportData := []byte{'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'E', 'd', 'g', 'e', 'l', 'e', 's', 's', ' ', 'S', 'y', 's', 't', 'e', 'm', 's', '!'}
	quote, err := tdx.GenerateQuote(handle, reportData)
	if err != nil {
		return err
	}

	if err := os.WriteFile("quote", quote, 0o644); err != nil {
		return err
	}
	log.Println("Successfully written quote")

	return nil
}
