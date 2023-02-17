package types

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
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
   │                         │     │     │ │                                       │ │    │     │  │           (2 bytes)            │ │
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

const (
	// TEETypeSGX is the type number referenced in the Quote header for SGX quotes.
	TEETypeSGX = 0x0

	// TEETypeTDX is the type number referenced in the Quote header for TDX quotes.
	TEETypeTDX = 0x81

	// PCK_ID_PCK_CERT_CHAIN is the CertificationData type holding the PCK cert chain (encoded in PEM, \0 byte terminated)
	PCK_ID_PCK_CERT_CHAIN = 5

	// PCK_ID_QE_REPORT_CERTIFICATION_DATA is the CertificationData type holding QEReportCertificationData data.
	PCK_ID_QE_REPORT_CERTIFICATION_DATA = 6
)

// sgxCertExtensionOID is the OID for Intel's custom x509 SGX extension.
var sgxCertExtensionOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}

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
	if quoteLength <= 636 {
		return SGXQuote4{}, fmt.Errorf("quote structure is too short to be parsed (received: %d bytes)", quoteLength)
	} else if quoteLength > 1048576 {
		return SGXQuote4{}, fmt.Errorf("quote is too large (over 1 MiB, received: %d bytes)", quoteLength)
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
	endSignature := uint64(636 + signatureLength)
	if endSignature > uint64(quoteLength) {
		return SGXQuote4{}, fmt.Errorf("quote SignatureLength is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", signatureLength, quoteLength-636)
	}

	signatureBytes := rawQuote[636:endSignature]

	// TODO: This should likely later be removed - we're basically just testing that we sliced correctly.
	// If you don't touch this code, it should either panic or be constant anyway.
	// Also, upgrade to uint64 so we can easier spot mistakes in case we overflow.
	expectedDataSize := uint64(signatureLength)
	actualDataSize := uint64(len(signatureBytes))
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
	CertificationData CertificationData // QEReportCertificationData
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

// Size returns the real size of CertificationData's Data field in bytes.
func (c CertificationData) Size() uint32 {
	switch data := c.Data.(type) {
	case QEReportCertificationData:
		// total := EnclaveReport + Signature + QEAuthData + CertificationData
		// len(EnclaveReport) := 384
		// len(Signature) := 64
		reportAndSigLen := 384 + 64
		// QEAuthData := len(ParsedDataSize) + len(Data)
		qeAuthLen := 2 + len(data.QEAuthData.Data)
		// CertificationData := len(ParsedDataSize) + len(Type) + len(Data.([]byte))
		certData, ok := data.CertificationData.Data.([]byte)
		if !ok {
			// should only happen when the Go struct was manually created
			// instead of parsed from a real quote
			return 0
		}
		certDataLen := len(certData) + 2 + 4

		return uint32(reportAndSigLen + qeAuthLen + certDataLen)
	case []byte:
		return uint32(len(data))
	default:
		// unknown type, return 0
		return 0
	}
}

// QEReportCertificationData holds the Quoting Enclave (QE) report, embedded as CertificationData in ECDSA256QuoteV4AuthData.
type QEReportCertificationData struct {
	EnclaveReport     EnclaveReport
	Signature         [64]byte // ECDSA256 signature
	QEAuthData        QEAuthData
	CertificationData CertificationData // PEM encoded PCKCertChain
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
	ParsedDataSize uint16 // This value is not need in Go quote verification
	Data           []byte
}

// parseSignature parses a signature (ECDSA256QuoteV4AuthData) from an SGXQuote4.
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
	endQEReportCertData := 134 + uint64(quoteSignature.CertificationData.ParsedDataSize)
	if endQEReportCertData > uint64(signatureLength) {
		return ECDSA256QuoteV4AuthData{}, fmt.Errorf("signature.CertificationData.ParsedDataSize is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", quoteSignature.CertificationData.ParsedDataSize, signatureLength-134)
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
		return QEReportCertificationData{}, fmt.Errorf("QEAuthData.ParsedDataSize is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", qeReport.QEAuthData.ParsedDataSize, qeReportCertDataLength-450)
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
		return CertificationData{}, fmt.Errorf("QEReportCertificationData.CertificationData.ParsedDataSize is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", qeAuthDataInnerCertData.ParsedDataSize, qeReportAuthDataCertDataLength-6)
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

// SGXExtensions are the x509 certificate extensions of a TDX PCK certificate.
type SGXExtensions struct {
	PPID               [16]byte
	TCB                PCKTCB
	PCEID              [2]byte
	FMSPC              [6]byte
	SGXType            int // 0 standard, 1 Scalable
	PlatformInstanceID [16]byte
	Configuration      PCKConfiguration
}

// PCKTCB describes the TCB of a TDX PCK certificate.
// They are part of the SGX extensions.
type PCKTCB struct {
	TCBSVN [16]int
	PCESVN uint32
	CPUSVN [16]byte
}

// PCKConfiguration describes the configuration of a TDX PCK certificate.
// They are part of the SGX extensions for multi user platforms.
type PCKConfiguration struct {
	DynamicPlatform bool
	CachedKeys      bool
	SMTEnabled      bool
}

// ParsePCKSGXExtensions parses the SGX extensions of a TDX PCK certificate.
func ParsePCKSGXExtensions(pckCert *x509.Certificate) (SGXExtensions, error) {
	var sgxExtension []byte
	for _, ext := range pckCert.Extensions {
		if ext.Id.Equal(sgxCertExtensionOID) {
			sgxExtension = ext.Value
			break
		}
	}
	if len(sgxExtension) == 0 {
		return SGXExtensions{}, errors.New("no SGX extension found in certificate")
	}

	var asn1Extensions asn1SGXExtensions
	if _, err := asn1.Unmarshal(sgxExtension, &asn1Extensions); err != nil {
		return SGXExtensions{}, fmt.Errorf("unmarshaling SGX extension: %w", err)
	}

	var ext SGXExtensions

	if len(asn1Extensions.PPID.Value) != 16 {
		return SGXExtensions{}, fmt.Errorf("invalid PPID length: %d", len(asn1Extensions.PPID.Value))
	}
	ext.PPID = [16]byte(asn1Extensions.PPID.Value)

	if len(asn1Extensions.PCEID.Value) != 2 {
		return SGXExtensions{}, fmt.Errorf("invalid PCEID length: %d", len(asn1Extensions.PCEID.Value))
	}
	ext.PCEID = [2]byte(asn1Extensions.PCEID.Value)

	ext.SGXType = int(asn1Extensions.SGXType.Value)

	if len(asn1Extensions.FMSPC.Value) != 6 {
		return SGXExtensions{}, fmt.Errorf("invalid FMSPC length: %d", len(asn1Extensions.FMSPC.Value))
	}
	ext.FMSPC = [6]byte(asn1Extensions.FMSPC.Value)

	// PlatformInstanceID is optional, but if present, must be 16 bytes.
	platformIDLen := len(asn1Extensions.PlatformInstanceID.Value)
	if platformIDLen > 0 {
		if platformIDLen != 16 {
			return SGXExtensions{}, fmt.Errorf("invalid PlatformInstanceID length: %d", platformIDLen)
		}
		ext.PlatformInstanceID = [16]byte(asn1Extensions.PlatformInstanceID.Value)
	}

	// Configuration is optional, but defaults to all false if not present.
	ext.Configuration.CachedKeys = asn1Extensions.Configuration.Configuration.CachedKeys.Value
	ext.Configuration.DynamicPlatform = asn1Extensions.Configuration.Configuration.DynamicPlatform.Value
	ext.Configuration.SMTEnabled = asn1Extensions.Configuration.Configuration.SMTEnabled.Value

	// TCBInfo is a sequence of TCB components.
	if len(asn1Extensions.TCB.TCBInfo.CPUSVN.Value) != 16 {
		return SGXExtensions{}, fmt.Errorf("invalid CPUSVN length: %d", len(asn1Extensions.TCB.TCBInfo.CPUSVN.Value))
	}
	ext.TCB.CPUSVN = [16]byte(asn1Extensions.TCB.TCBInfo.CPUSVN.Value)
	ext.TCB.PCESVN = uint32(asn1Extensions.TCB.TCBInfo.PCESVN.Value)

	ext.TCB.TCBSVN[0] = asn1Extensions.TCB.TCBInfo.Comp01SVN.Value
	ext.TCB.TCBSVN[1] = asn1Extensions.TCB.TCBInfo.Comp02SVN.Value
	ext.TCB.TCBSVN[2] = asn1Extensions.TCB.TCBInfo.Comp03SVN.Value
	ext.TCB.TCBSVN[3] = asn1Extensions.TCB.TCBInfo.Comp04SVN.Value
	ext.TCB.TCBSVN[4] = asn1Extensions.TCB.TCBInfo.Comp05SVN.Value
	ext.TCB.TCBSVN[5] = asn1Extensions.TCB.TCBInfo.Comp06SVN.Value
	ext.TCB.TCBSVN[6] = asn1Extensions.TCB.TCBInfo.Comp07SVN.Value
	ext.TCB.TCBSVN[7] = asn1Extensions.TCB.TCBInfo.Comp08SVN.Value
	ext.TCB.TCBSVN[8] = asn1Extensions.TCB.TCBInfo.Comp09SVN.Value
	ext.TCB.TCBSVN[9] = asn1Extensions.TCB.TCBInfo.Comp10SVN.Value
	ext.TCB.TCBSVN[10] = asn1Extensions.TCB.TCBInfo.Comp11SVN.Value
	ext.TCB.TCBSVN[11] = asn1Extensions.TCB.TCBInfo.Comp12SVN.Value
	ext.TCB.TCBSVN[12] = asn1Extensions.TCB.TCBInfo.Comp13SVN.Value
	ext.TCB.TCBSVN[13] = asn1Extensions.TCB.TCBInfo.Comp14SVN.Value
	ext.TCB.TCBSVN[14] = asn1Extensions.TCB.TCBInfo.Comp15SVN.Value
	ext.TCB.TCBSVN[15] = asn1Extensions.TCB.TCBInfo.Comp16SVN.Value

	return ext, nil
}

// asn1SGXExtensions holds the ASN.1 encoded SGX extensions of a TDX PCK cert.
type asn1SGXExtensions struct {
	PPID               asn1OctetString   `asn1:"tag:SEQUENCE"`
	TCB                asn1TCB           `asn1:"tag:SEQUENCE"`
	PCEID              asn1OctetString   `asn1:"tag:SEQUENCE"`
	FMSPC              asn1OctetString   `asn1:"tag:SEQUENCE"`
	SGXType            asn1Enumerated    `asn1:"tag:SEQUENCE"`
	PlatformInstanceID asn1OctetString   `asn1:"tag:SEQUENCE,optional"`
	Configuration      asn1Configuration `asn1:"tag:SEQUENCE,optional"`
}

type asn1TCB struct {
	TCBOid  asn1.ObjectIdentifier `asn1:"tag:OBJECT_IDENTIFIER"`
	TCBInfo asn1TCBInfo           `asn1:"tag:SEQUENCE"`
}

type asn1TCBInfo struct {
	Comp01SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp02SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp03SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp04SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp05SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp06SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp07SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp08SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp09SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp10SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp11SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp12SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp13SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp14SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp15SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	Comp16SVN asn1Integer     `asn1:"tag:SEQUENCE"`
	PCESVN    asn1Integer     `asn1:"tag:SEQUENCE"`
	CPUSVN    asn1OctetString `asn1:"tag:SEQUENCE"`
}

type asn1Configuration struct {
	ConfigurationOid asn1.ObjectIdentifier    `asn1:"tag:OBJECT_IDENTIFIER"`
	Configuration    asn1ConfigurationOptions `asn1:"tag:SEQUENCE"`
}

type asn1ConfigurationOptions struct {
	DynamicPlatform asn1Boolean `asn1:"tag:SEQUENCE,optional"`
	CachedKeys      asn1Boolean `asn1:"tag:SEQUENCE,optional"`
	SMTEnabled      asn1Boolean `asn1:"tag:SEQUENCE,optional"`
}

type asn1OctetString struct {
	Oid   asn1.ObjectIdentifier `asn1:"tag:OBJECT_IDENTIFIER"`
	Value []byte                `asn1:"tag:OCTET_STRING"`
}

type asn1Integer struct {
	Oid   asn1.ObjectIdentifier `asn1:"tag:OBJECT_IDENTIFIER"`
	Value int                   `asn1:"tag:INTEGER"`
}

type asn1Boolean struct {
	Oid   asn1.ObjectIdentifier `asn1:"tag:OBJECT_IDENTIFIER"`
	Value bool                  `asn1:"tag:BOOLEAN"`
}

type asn1Enumerated struct {
	Oid   asn1.ObjectIdentifier `asn1:"tag:OBJECT_IDENTIFIER"`
	Value asn1.Enumerated       `asn1:"tag:0a"`
}
