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
	Version            uint16
	AttestationKeyType uint16
	TEEType            uint32 // 0x0 = SGX, 0x81 = TDX
	Reserved           uint32
	VendorID           [16]byte
	UserData           [20]byte
}

type SGXReport2 struct {
	TCBSVN         [16]byte
	MRSEAM         [48]byte    // SHA384
	MRSIGNERSEAM   [48]byte    // SHA384
	SEAMAttributes uint64      // TEE Attributes: In C code that's a [2]uint32
	TDAttributes   uint64      // TEE Attributes: In C code that's a [2]uint32
	XFAM           uint64      // TEE Attributes: In C code that's a [2]uint32
	MRTD           [48]byte    // SHA384
	MRCONFIG       [48]byte    // SHA384
	MROWNER        [48]byte    // SHA384
	MROWNERCONFIG  [48]byte    // SHA384
	RTMR           [4][48]byte // 4x SHA384 - runtime measurements
	Reportdata     [64]byte    // Likely UserData from the original TDREPORT
}

type SGXQuote4 struct {
	Header          SGXQuote4Header
	Body            SGXReport2
	SignatureLength uint32
	Signature       []byte
}

func ParseQuote(rawQuote []byte) SGXQuote4 {
	quoteHeader := SGXQuote4Header{
		Version:            binary.LittleEndian.Uint16(rawQuote[0:2]),
		AttestationKeyType: binary.LittleEndian.Uint16(rawQuote[2:4]),
		TEEType:            binary.LittleEndian.Uint32(rawQuote[4:8]),
		Reserved:           binary.LittleEndian.Uint32(rawQuote[8:12]),
		VendorID:           [16]byte(rawQuote[12:28]),
		UserData:           [20]byte(rawQuote[28:48]),
	}

	body := SGXReport2{
		TCBSVN:         [16]byte(rawQuote[48:64]),
		MRSEAM:         [48]byte(rawQuote[64:112]),
		MRSIGNERSEAM:   [48]byte(rawQuote[112:160]),
		SEAMAttributes: binary.LittleEndian.Uint64(rawQuote[160:168]),
		TDAttributes:   binary.LittleEndian.Uint64(rawQuote[168:176]),
		XFAM:           binary.LittleEndian.Uint64(rawQuote[176:184]),
		MRTD:           [48]byte(rawQuote[184:232]),
		MRCONFIG:       [48]byte(rawQuote[232:280]),
		MROWNER:        [48]byte(rawQuote[280:328]),
		MROWNERCONFIG:  [48]byte(rawQuote[328:376]),
		RTMR:           [4][48]byte{[48]byte(rawQuote[376:424]), [48]byte(rawQuote[424:472]), [48]byte(rawQuote[472:520]), [48]byte(rawQuote[520:568])},
		Reportdata:     [64]byte(rawQuote[568:632]),
	}

	// Good job Intel for f***ing up the calculation in the source. The offset here is NOT 656, but 632.
	// You can reproduce this by seeing that the Header is 48 bytes large, and the report Body 584 bytes.
	// 584 + 48 is 632. That's not 656, Intel! 🤦🏻‍♂️
	signatureLength := binary.LittleEndian.Uint32(rawQuote[632:636])

	return SGXQuote4{
		Header:          quoteHeader,
		Body:            body,
		SignatureLength: signatureLength,
		Signature:       rawQuote[636 : 636+signatureLength],
	}
}

/*
	Based on:
	https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteVerification/QVL/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h
*/

type ECDSA256QuoteV4AuthData struct {
	Signature         [64]byte
	PublicKey         [64]byte
	CertificationData CertificationData
}

type CertificationData struct {
	Type           uint16
	ParsedDataSize uint32
	// Can be:
	// -> QEReportCertificationData (if type == 6: PCK_ID_QE_REPORT_CERTIFICATION_DATA)
	//    -> Certificates (if type == 5: PCK_ID_PCK_CERT_CHAIN)
	Data interface{}
}

type EnclaveReport struct {
	CPUSVN     [16]byte
	MiscSelect uint32
	Reserved1  [28]byte
	Attributes [16]byte // TODO: Is this an uint128?
	MRENCLAVE  [32]byte
	Reserved2  [32]byte
	MRSIGNER   [32]byte
	Reserved3  [96]byte
	isvProdID  uint16
	isvSVN     uint16
	Reserved4  [60]byte
	ReportData [64]byte
}

type QEAuthData struct {
	ParsedDataSize uint16
	Data           []byte
}

type QEReportCertificationData struct {
	EnclaveReport     EnclaveReport
	Signature         [64]byte // ECDSA256 signature
	QEAuthData        QEAuthData
	CertificationData CertificationData
}

func ParseSignature(signature []byte) ECDSA256QuoteV4AuthData {
	return ECDSA256QuoteV4AuthData{
		Signature: [64]byte(signature[0:64]),   // ECDSA256 signature
		PublicKey: [64]byte(signature[64:128]), // ECDSA256 public key
		CertificationData: CertificationData{
			Type:           binary.LittleEndian.Uint16(signature[128:130]),
			ParsedDataSize: binary.LittleEndian.Uint32(signature[130:134]),
			Data: QEReportCertificationData{
				EnclaveReport: EnclaveReport{
					CPUSVN:     [16]byte(signature[134:150]),
					MiscSelect: binary.LittleEndian.Uint32(signature[150:154]),
					Reserved1:  [28]byte(signature[154:182]),
					Attributes: [16]byte(signature[182:198]),
					MRENCLAVE:  [32]byte(signature[198:230]),
					Reserved2:  [32]byte(signature[230:262]),
					MRSIGNER:   [32]byte(signature[262:294]),
					Reserved3:  [96]byte(signature[294:390]),
					isvProdID:  binary.LittleEndian.Uint16(signature[390:392]),
					isvSVN:     binary.LittleEndian.Uint16(signature[392:394]),
					Reserved4:  [60]byte(signature[394:454]),
					ReportData: [64]byte(signature[454:518]),
				},
				Signature: [64]byte(signature[518:582]),
				QEAuthData: QEAuthData{
					ParsedDataSize: binary.LittleEndian.Uint16(signature[582:584]), // TODO: Make this dynamic, but this is likely 32 bytes.
					Data:           signature[584:616],
				},
				CertificationData: CertificationData{
					Type:           binary.LittleEndian.Uint16(signature[616:618]),
					ParsedDataSize: binary.LittleEndian.Uint32(signature[618:622]),
					Data:           signature[622 : 622+binary.LittleEndian.Uint32(signature[618:622])],
				},
			},
		},
	}
}
