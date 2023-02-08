/*
# Intel TDX Quote Verification

This package provides a simple interface to verify Intel TDX quotes.

TODO: Verify the following statement is true:
Since functions in this package communicate with Intel's PCS,
you must have a valid Intel Attestation Service API key to use this package.

Attestation of a TDX attestation statement follows these steps:

  - Retrieve TDX collateral from Intel's PCS.

    This includes the PCK CRL chain, TCB Info, QE Identity information, and Intel's Root CA CRL.

  - Verify enclave PCK cert chain using PCK CRL chain, Root CA CRL, and trusted Root CA.

  - Verify TCB Info using TCB Signing Cert, Root CA CRL, and trusted Root CA

  - Verify QE Identity using TCB Signing Cert, Root CA CRL, and trusted Root CA

  - Verify quote using PCK Cert, PCK CRL chain, TCB Info, and QE Identity
*/
package verification

import (
	"encoding/binary"
)

/*
	Based on:
	https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L113
	https://github.com/intel/linux-sgx/blob/d5e10dfbd7381bcd47eb25d2dc1d2da4e9a91e70/common/inc/sgx_report2.h#L61
*/

type SGXQuote4Header struct {
	version            uint16
	attestationKeyType uint16
	teeType            uint32 // 0x0 = SGX, 0x81 = TDX
	reserved           uint32
	vendorID           [16]byte
	userData           [20]byte
}

type SGXReport2 struct {
	tcbSVN         [16]byte
	mrseam         [48]byte    // SHA384
	mrsignerseam   [48]byte    // SHA384
	seamAttributes uint64      // TEE Attributes: In C code that's a [2]uint32
	tdAttributes   uint64      // TEE Attributes: In C code that's a [2]uint32
	xfam           uint64      // TEE Attributes: In C code that's a [2]uint32
	mrtd           [48]byte    // SHA384
	mrconfigid     [48]byte    // SHA384
	mrowner        [48]byte    // SHA384
	mrownerconfig  [48]byte    // SHA384
	rtmr           [4][48]byte // 4x SHA384 - runtime measurements
	reportdata     [64]byte    // Likely userData from the original TDREPORT
}

type SGXQuote4 struct {
	header          SGXQuote4Header
	body            SGXReport2
	signatureLength uint32
	signature       []byte
}

func ParseQuote(rawQuote []byte) SGXQuote4 {
	quoteHeader := SGXQuote4Header{
		version:            binary.LittleEndian.Uint16(rawQuote[0:2]),
		attestationKeyType: binary.LittleEndian.Uint16(rawQuote[2:4]),
		teeType:            binary.LittleEndian.Uint32(rawQuote[4:8]),
		reserved:           binary.LittleEndian.Uint32(rawQuote[8:12]),
		vendorID:           [16]byte(rawQuote[12:28]),
		userData:           [20]byte(rawQuote[28:48]),
	}

	body := SGXReport2{
		tcbSVN:         [16]byte(rawQuote[48:64]),
		mrseam:         [48]byte(rawQuote[64:112]),
		mrsignerseam:   [48]byte(rawQuote[112:160]),
		seamAttributes: binary.LittleEndian.Uint64(rawQuote[160:168]),
		tdAttributes:   binary.LittleEndian.Uint64(rawQuote[168:176]),
		xfam:           binary.LittleEndian.Uint64(rawQuote[176:184]),
		mrtd:           [48]byte(rawQuote[184:232]),
		mrconfigid:     [48]byte(rawQuote[232:280]),
		mrowner:        [48]byte(rawQuote[280:328]),
		mrownerconfig:  [48]byte(rawQuote[328:376]),
		rtmr:           [4][48]byte{[48]byte(rawQuote[376:424]), [48]byte(rawQuote[424:472]), [48]byte(rawQuote[472:520]), [48]byte(rawQuote[520:568])},
		reportdata:     [64]byte(rawQuote[568:632]),
	}

	// Good job Intel for f***ing up the calculation in the source. The offset here is NOT 656, but 632.
	// You can reproduce this by seeing that the header is 48 bytes large, and the report body 584 bytes.
	// 584 + 48 is 632. That's not 656, Intel! 🤦🏻‍♂️
	signatureLength := binary.LittleEndian.Uint32(rawQuote[632:636])

	return SGXQuote4{
		header:          quoteHeader,
		body:            body,
		signatureLength: signatureLength,
		signature:       rawQuote[636:signatureLength],
	}
}
