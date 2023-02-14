package main

import (
	"context"
	"fmt"
	"os"

	"github.com/edgelesssys/go-tdx-qpl/verification/pcs"
)

func main() {
	if err := pcsConnection(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func pcsConnection() error {
	client, err := pcs.New()
	if err != nil {
		return err
	}

	crl, intermediateCert, err := client.GetPCKCRL(context.Background(), pcs.TDXPlatform)
	if err != nil {
		return err
	}
	fmt.Println("Fetched and verified PCK CRL")
	fmt.Printf("CRL:\n%+v\n", crl)
	fmt.Printf("Intermediate Cert:\n%+v\n", intermediateCert)

	tcbInfo, err := client.GetTCBInfo(context.Background(), [6]byte{0x00, 0x80, 0x6F, 0x05, 0x00, 0x00})
	if err != nil {
		return err
	}
	fmt.Println("Fetched and verified TCB Info")
	fmt.Printf("TCB Info:\n%+v\n", tcbInfo)

	qeIdentity, err := client.GetQEIdentity(context.Background())
	if err != nil {
		return err
	}
	fmt.Println("Fetched and verified QE Identity")
	fmt.Printf("QE Identity:\n%+v\n", qeIdentity)
	return nil
}
