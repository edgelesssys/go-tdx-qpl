package verification

import (
	"encoding/binary"
	"fmt"
)

/*
   If you found this code, my condolences! If you are about to maintain this code, I wish you very well not to lose yourself.

   You are about to deep-dive into the inner technical structure of Intel TDX/SGX.
   This parser tries to reimplement the same structs as the original QvL code this was inspired from, using the original
   namings as close as possible. The implemented API version is v4, others are not supported yet.
   The sources for the struct for each part are given in the comments below.

   To give a *rough* understanding on what this looks like and what function does what, see this graphic I made below:


                                   ┌──────────────────────────┐                           ┌─────────────────────────┐
                                   │                          │                           │                         │
                                   │                          ▼                           │                         ▼
           SGXQuote4               │                 ECDSA256QuoteV4Data                  │            QEReportCertificationData
           ParseQuote              │                   parseSignature                     │          parseQEReportCertificationData
   ┌─────────────────────────┐     │     ┌───────────────────────────────────────────┐    │     ┌─────────────────────────────────────┐
   │     SGXQuote4Header     │     │     │                Signature                  │    │     │                                     │
   │       (48 bytes)        │     │     │                (64 bytes)                 │    │     │                                     │
   ├─────────────────────────┤     │     ├───────────────────────────────────────────┤    │     │            EnclaveReport            │
   │                         │     │     │                PublicKey                  │    │     │             (384 bytes)             │
   │       SGXREPORT2        │     │     │                (64 bytes)                 │    │     │                                     │
   │       (TDREPORT)        │     │     ├───────────────────────────────────────────┤    │     │                                     │
   │       (584 bytes)       │     │     │             CertificationData             │    │     ├─────────────────────────────────────┤
   │                         │     │     │ ┌───────────────────────────────────────┐ │    │     │             Signature               │
   │                         │     │     │ │                 Type                  │ │    │     │             (64 bytes)              │
   ├─────────────────────────┤     │     │ │               (2 bytes)               │ │    │     ├─────────────────────────────────────┤
   │     SignatureLength     │     │     │ │                                       │ │    │     │             QEAuthData              │
   │        (4 bytes)        │     │     │ │               type == 6               │ │    │     │  ┌────────────────────────────────┐ │
   ├─────────────────────────┤     │     │ │  PCK_ID_QE_REPORT_CERTIFICATION_DATA  │ │    │     │  │        ParsedDataSize          │ │
   │                         │     │     │ │                                       │ │    │     │  │           (4 bytes)            │ │
   │                         │     │     │ ├───────────────────────────────────────┤ │    │     │  ├────────────────────────────────┤ │
   │                         │     │     │ │            ParsedDataSize             │ │    │     │  │             Data               │ │
   │                         │     │     │ │               (4 bytes)               │ │    │     │  │          (variable)            │ │
   │       Signature         │     │     │ ├───────────────────────────────────────┤ │    │     │  └────────────────────────────────┘ │
   │ ECDSA256QuoteV4AuthData │     │     │ │                 Data                  │ │    │     │                                     │
   │       (variable)        ├─────┘     │ │              (variable)               │ │    │     ├─────────────────────────────────────┤
   │                         │           │ │                                       │ │    │     │          CertificationData          │
   │                         │           │ │        QEReportCertificationData      ├─┼────┘     │ parseQEReportInnerCertificationData │
   │                         │           │ │                                       │ │          │                                     │
   │                         │           │ └───────────────────────────────────────┘ │          │ ┌─────────────────────────────────┐ │
   │                         │           │                                           │          │ │              Type               │ │
   └─────────────────────────┘           └───────────────────────────────────────────┘          │ │            (2 bytes)            │ │
                                                                                                │ │                                 │ │
                                                                                                │ │            type == 5            │ │
                                                                                                │ │      PCK_ID_PCK_CERT_CHAIN      │ │
                                                                                                │ ├─────────────────────────────────┤ │
                                                                                                │ │         ParsedDataSize          │ │
                                                                                                │ │            (4 bytes)            │ │
                                                                                                │ ├─────────────────────────────────┤ │
                                                                                                │ │              Data               │ │
                                                                                                │ │            (variable)           │ │
                                                                                                │ │                                 │ │
                                                                                                │ │            []byte               │ │
                                                                                                │ │   (contains a PEM certificate)  │ │
                                                                                                │ │      terminated with \0 byte    │ │
                                                                                                │ │                                 │ │
                                                                                                │ └─────────────────────────────────┘ │
                                                                                                │                                     │
                                                                                                └─────────────────────────────────────┘
*/

/*
   TDX (SGX Quote 4 / SGX Report 2) Quote parser
   Based on:
   https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L113
   https://github.com/intel/linux-sgx/blob/d5e10dfbd7381bcd47eb25d2dc1d2da4e9a91e70/common/inc/sgx_report2.h#L61
*/

// TEETypeSGX is the type number referenced in the Quote header for SGX quotes.
const TEETypeSGX = 0x0

// TEETypeTDX is the type number referenced in the Quote header for TDX quotes.
const TEETypeTDX = 0x81

// PCK_ID_PCK_CERT_CHAIN is the CertificationData type holding the PCK cert chain (encoded in PEM, \0 byte terminated)
const PCK_ID_PCK_CERT_CHAIN = 5

// PCK_ID_QE_REPORT_CERTIFICATION_DATA is the CertificationData type holding QEReportCertificationData data.
const PCK_ID_QE_REPORT_CERTIFICATION_DATA = 6

// SGXQuote4Header is the header of an SGX/TDX quote compatible with v4 of the TrustedPlatform API.
type SGXQuote4Header struct {
	Version            uint16
	AttestationKeyType uint16
	TEEType            uint32 // 0x0 = SGX, 0x81 = TDX
	Reserved           uint32
	VendorID           [16]byte
	UserData           [20]byte
}

// SGXReport2 is a TDReport for Intel TDX platforms, originally passed into the quote for signing.
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
	ReportData     [64]byte    // Likely UserData from the original TDREPORT
}

// SGXQuote4 is an SGX/TDX quote compatible with v4 of the TrustedPlatform API.
type SGXQuote4 struct {
	Header          SGXQuote4Header
	Body            SGXReport2
	SignatureLength uint32
	Signature       ECDSA256QuoteV4AuthData
}

// ParseQuote parses an Intel TDX v4 Quote. The expected input is the complete quote.
func ParseQuote(rawQuote []byte) (SGXQuote4, error) {
	quoteLength := len(rawQuote)
	if len(rawQuote) <= 636 {
		return SGXQuote4{}, fmt.Errorf("quote structure is too short to be parsed (received: %d bytes)", quoteLength)
	}

	quoteHeader := SGXQuote4Header{
		Version:            binary.LittleEndian.Uint16(rawQuote[0:2]),
		AttestationKeyType: binary.LittleEndian.Uint16(rawQuote[2:4]),
		TEEType:            binary.LittleEndian.Uint32(rawQuote[4:8]),
		Reserved:           binary.LittleEndian.Uint32(rawQuote[8:12]),
		VendorID:           [16]byte(rawQuote[12:28]),
		UserData:           [20]byte(rawQuote[28:48]),
	}

	if quoteHeader.Version != 4 {
		return SGXQuote4{}, fmt.Errorf("quote version is not 4 (got: %d)", quoteHeader.Version)
	}

	if quoteHeader.TEEType != TEETypeTDX {
		return SGXQuote4{}, fmt.Errorf("quote does not appear to be a TDX quote (expected TEEType: %d, got: %d)", TEETypeTDX, quoteHeader.TEEType)
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
		ReportData:     [64]byte(rawQuote[568:632]),
	}

	signatureLength := binary.LittleEndian.Uint32(rawQuote[632:636])
	endSignature := 636 + signatureLength
	if int(endSignature) > quoteLength {
		return SGXQuote4{}, fmt.Errorf("quote SignatureLength is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", endSignature-636, quoteLength-636)
	}

	signatureBytes := rawQuote[636 : 636+signatureLength]
	expectedDataSize := int(signatureLength)
	actualDataSize := len(signatureBytes)
	if expectedDataSize != actualDataSize {
		return SGXQuote4{}, fmt.Errorf("quote signature does not match the defined size (expected: %d bytes, got: %d bytes)", expectedDataSize, actualDataSize)
	}
	signature, err := parseSignature(signatureBytes)
	if err != nil {
		return SGXQuote4{}, fmt.Errorf("failed parsing quote signature: %w", err)
	}

	return SGXQuote4{
		Header:          quoteHeader,
		Body:            body,
		SignatureLength: signatureLength,
		Signature:       signature,
	}, nil
}

/*
   TDX Quote Signature Parsing
   Based on:
   https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteVerification/QVL/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h
*/

// ECDSA256QuoteV4AuthData is the signature of an Intel TDX v4 quote.
type ECDSA256QuoteV4AuthData struct {
	Signature         [64]byte
	PublicKey         [64]byte
	CertificationData CertificationData
}

// CertificationData is a generic Data wrapper from Intel's library.
// In our case (API v4, TDX), this usually is:
// QEReportCertificationData (type == 6: PCK_ID_QE_REPORT_CERTIFICATION_DATA)
// PEM certificate chain (type == 5: PCK_ID_PCK_CERT_CHAIN)
type CertificationData struct {
	Type           uint16
	ParsedDataSize uint32
	Data           any
}

// QEReportCertificationData holds the Quoting Enclave (QE) report, embedded as CertificationData in ECDSA256QuoteV4AuthData.
type QEReportCertificationData struct {
	EnclaveReport     EnclaveReport
	Signature         [64]byte // ECDSA256 signature
	QEAuthData        QEAuthData
	CertificationData CertificationData
}

// EnclaveReport is the report of a Quoting Enclave for SGX and TDX. For TDX, this appears to be static values.
type EnclaveReport struct {
	CPUSVN     [16]byte
	MiscSelect uint32
	Reserved1  [28]byte
	Attributes [16]byte // TODO: Is this an uint128?
	MRENCLAVE  [32]byte
	Reserved2  [32]byte
	MRSIGNER   [32]byte
	Reserved3  [96]byte
	ISVProdID  uint16
	ISVSVN     uint16
	Reserved4  [60]byte
	ReportData [64]byte
}

// QEAuthData holds the Quoting Enclave (QE) authentication data. For TDX, this appears to be static data.
type QEAuthData struct {
	ParsedDataSize uint16
	Data           []byte
}

// parseSignature parses a signature (ECDSA256QuoteV4AuthData) from a SGXQuote4.
func parseSignature(signature []byte) (ECDSA256QuoteV4AuthData, error) {
	signatureLength := len(signature)
	if signatureLength < 134 {
		return ECDSA256QuoteV4AuthData{}, fmt.Errorf("signature is too short to be parsed (received: %d bytes)", signatureLength)
	}

	quoteSignature := ECDSA256QuoteV4AuthData{
		Signature: [64]byte(signature[0:64]),   // ECDSA256 signature
		PublicKey: [64]byte(signature[64:128]), // ECDSA256 public key
		CertificationData: CertificationData{
			Type:           binary.LittleEndian.Uint16(signature[128:130]),
			ParsedDataSize: binary.LittleEndian.Uint32(signature[130:134]),
		},
	}

	if quoteSignature.CertificationData.Type != PCK_ID_QE_REPORT_CERTIFICATION_DATA {
		return ECDSA256QuoteV4AuthData{}, fmt.Errorf("signature.CertificationData.Type is of unexpected (expected PCK_ID_QE_REPORT_CERTIFICATION_DATA (6), got %d)", quoteSignature.CertificationData.Type)
	}

	// Upgrade to uint64 since we could overflow if ParsedDataSize is close to the top of uint32.
	endQEReportCertData := uint64(134 + quoteSignature.CertificationData.ParsedDataSize)
	if endQEReportCertData > uint64(signatureLength) {
		return ECDSA256QuoteV4AuthData{}, fmt.Errorf("signature.CertificationData.ParsedDataSize is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", endQEReportCertData-134, signatureLength-134)
	}

	qeReportCertDataBytes := signature[134:endQEReportCertData]
	// TODO: This should likely later be removed - we're basically just testing that we sliced correctly.
	// If you don't touch this code, it should either panic or be constant anyway.
	// Also, upgrade to uint64 so we can easier spot mistakes in case we overflow.
	expectedDataSize := uint64(quoteSignature.CertificationData.ParsedDataSize)
	actualDataSize := uint64(len(qeReportCertDataBytes))
	if expectedDataSize != actualDataSize {
		return ECDSA256QuoteV4AuthData{}, fmt.Errorf("signature.CertificationData.Data does not match the defined size (expected: %d bytes, got: %d bytes)", expectedDataSize, actualDataSize)
	}

	qeReportCertData, err := parseQEReportCertificationData(qeReportCertDataBytes)
	if err != nil {
		return ECDSA256QuoteV4AuthData{}, err
	}

	quoteSignature.CertificationData.Data = qeReportCertData

	return quoteSignature, nil
}

// parseQEReportCertificationData parses a Quoting Enclave (QE) report embedded as CertificationData in ECDSA256QuoteV4AuthData.
func parseQEReportCertificationData(qeReportCertData []byte) (QEReportCertificationData, error) {
	qeReportCertDataLength := len(qeReportCertData)
	if qeReportCertDataLength < 450 {
		return QEReportCertificationData{}, fmt.Errorf("QEReportCertificationData is too short to be parsed (received: %d bytes)", qeReportCertDataLength)
	}

	qeReport := QEReportCertificationData{
		EnclaveReport: EnclaveReport{
			CPUSVN:     [16]byte(qeReportCertData[0:16]),
			MiscSelect: binary.LittleEndian.Uint32(qeReportCertData[16:20]),
			Reserved1:  [28]byte(qeReportCertData[20:48]),
			Attributes: [16]byte(qeReportCertData[48:64]),
			MRENCLAVE:  [32]byte(qeReportCertData[64:96]),
			Reserved2:  [32]byte(qeReportCertData[96:128]),
			MRSIGNER:   [32]byte(qeReportCertData[128:160]),
			Reserved3:  [96]byte(qeReportCertData[160:256]),
			ISVProdID:  binary.LittleEndian.Uint16(qeReportCertData[256:258]),
			ISVSVN:     binary.LittleEndian.Uint16(qeReportCertData[258:260]),
			Reserved4:  [60]byte(qeReportCertData[260:320]),
			ReportData: [64]byte(qeReportCertData[320:384]),
		},
		Signature: [64]byte(qeReportCertData[384:448]),
		QEAuthData: QEAuthData{
			ParsedDataSize: binary.LittleEndian.Uint16(qeReportCertData[448:450]),
		},
	}

	// Upgrade to uint32 since we could overflow if ParsedDataSize is close to the top of uint16.
	endQEAuthData := 450 + uint32(qeReport.QEAuthData.ParsedDataSize)
	if endQEAuthData > uint32(qeReportCertDataLength) {
		return QEReportCertificationData{}, fmt.Errorf("QEAuthData.ParsedDataSize is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", qeReport.QEAuthData.ParsedDataSize-450, qeReportCertDataLength-450)
	}

	qeAuthData := qeReportCertData[450:endQEAuthData]
	// TODO: This should likely later be removed - we're basically just testing that we sliced correctly.
	// If you don't touch this code, it should either panic or be constant anyway.
	// Also, upgrade to uint64 so we can easier spot mistakes in case we overflow.
	expectedDataSize := uint64(qeReport.QEAuthData.ParsedDataSize)
	actualDataSize := uint64(len(qeAuthData))
	if expectedDataSize != actualDataSize {
		return QEReportCertificationData{}, fmt.Errorf("QEAuthData.Data does not match the defined size (expected: %d bytes, got: %d bytes)", expectedDataSize, actualDataSize)
	}
	qeReport.QEAuthData.Data = qeAuthData

	// Parse CertificationData in an extra function to keep this function itself cleaner and readable.
	// There's no expected data size here, so the callee does the size check at the beginning.
	qeReportInnerCertData, err := parseQEReportInnerCertificationData(qeReportCertData[endQEAuthData:])
	if err != nil {
		return QEReportCertificationData{}, err
	}
	qeReport.CertificationData = qeReportInnerCertData

	return qeReport, nil
}

// parseQEReportInnerCertificationData parses CertificationData from a Quoting Enclave (QE) report (QEReportCertificationData).
// This has been externalized into an extra function mainly for readability.
func parseQEReportInnerCertificationData(qeReportAuthDataCertData []byte) (CertificationData, error) {
	qeReportAuthDataCertDataLength := len(qeReportAuthDataCertData)
	if qeReportAuthDataCertDataLength <= 6 {
		return CertificationData{}, fmt.Errorf("QEReportCertificationData.CertificationData is too short to be parsed (received: %d bytes)", qeReportAuthDataCertDataLength)
	}
	qeAuthDataInnerCertData := CertificationData{
		Type:           binary.LittleEndian.Uint16(qeReportAuthDataCertData[0:2]),
		ParsedDataSize: binary.LittleEndian.Uint32(qeReportAuthDataCertData[2:6]),
	}

	if qeAuthDataInnerCertData.Type != PCK_ID_PCK_CERT_CHAIN {
		return CertificationData{}, fmt.Errorf("signature.CertificationData.Type is of unexpected (expected PCK_ID_PCK_CERT_CHAIN (5), got %d)", qeAuthDataInnerCertData.Type)
	}

	// Upgrade to uint64 since we could overflow if ParsedDataSize is close to the top of uint32.
	endQEAuthDataInnerCertData := 6 + uint64(qeAuthDataInnerCertData.ParsedDataSize)
	if endQEAuthDataInnerCertData > uint64(qeReportAuthDataCertDataLength) {
		return CertificationData{}, fmt.Errorf("QEReportCertificationData.CertificationData.ParsedDataSize is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", qeAuthDataInnerCertData.ParsedDataSize-6, qeReportAuthDataCertDataLength-6)
	}

	data := qeReportAuthDataCertData[6:endQEAuthDataInnerCertData]
	// TODO: This should likely later be removed - we're basically just testing that we sliced correctly.
	// If you don't touch this code, it should either panic or be constant anyway.
	// Also, upgrade to uint64 so we can easier spot mistakes in case we overflow.
	expectedParsedDataSize := uint64(qeAuthDataInnerCertData.ParsedDataSize)
	actualParsedDataSize := uint64(len(data))
	if expectedParsedDataSize != actualParsedDataSize {
		return CertificationData{}, fmt.Errorf("QEReportCertificationData.CertificationData.Data does not match the defined size (expected: %d bytes, got: %d bytes)", expectedParsedDataSize, actualParsedDataSize)
	}

	qeAuthDataInnerCertData.Data = data

	return qeAuthDataInnerCertData, nil
}
