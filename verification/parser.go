package verification

import (
	"encoding/binary"
	"fmt"
)

/*
	TDX (SGX Quote 4 / SGX Report 2) Quote parser
	Based on:
	https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L113
	https://github.com/intel/linux-sgx/blob/d5e10dfbd7381bcd47eb25d2dc1d2da4e9a91e70/common/inc/sgx_report2.h#L61
*/

const TEETypeSGX = 0x0
const TEETypeTDX = 0x81

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
	Signature       ECDSA256QuoteV4AuthData
}

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
		Reportdata:     [64]byte(rawQuote[568:632]),
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

	endQEReportCertData := 134 + quoteSignature.CertificationData.ParsedDataSize
	if int(endQEReportCertData) > signatureLength {
		return ECDSA256QuoteV4AuthData{}, fmt.Errorf("signature.CertificationData.ParsedDataSize is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", endQEReportCertData-134, signatureLength-134)
	}

	qeReportCertDataBytes := signature[134 : 134+quoteSignature.CertificationData.ParsedDataSize]
	expectedDataSize := int(quoteSignature.CertificationData.ParsedDataSize)
	actualDataSize := len(qeReportCertDataBytes)
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
			isvProdID:  binary.LittleEndian.Uint16(qeReportCertData[256:258]),
			isvSVN:     binary.LittleEndian.Uint16(qeReportCertData[258:260]),
			Reserved4:  [60]byte(qeReportCertData[260:320]),
			ReportData: [64]byte(qeReportCertData[320:384]),
		},
		Signature: [64]byte(qeReportCertData[384:448]),
		QEAuthData: QEAuthData{
			ParsedDataSize: binary.LittleEndian.Uint16(qeReportCertData[448:450]),
		},
	}

	endQEAuthData := 450 + qeReport.QEAuthData.ParsedDataSize
	if int(endQEAuthData) > qeReportCertDataLength {
		return QEReportCertificationData{}, fmt.Errorf("QEAuthData.ParsedDataSize is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", qeReport.QEAuthData.ParsedDataSize-450, qeReportCertDataLength-450)
	}

	qeAuthData := qeReportCertData[450:endQEAuthData]
	expectedDataSize := int(qeReport.QEAuthData.ParsedDataSize)
	actualDataSize := len(qeAuthData)
	if expectedDataSize != actualDataSize {
		return QEReportCertificationData{}, fmt.Errorf("QEAuthData.Data does not match the defined size (expected: %d bytes, got: %d bytes)", expectedDataSize, actualDataSize)
	}
	qeReport.QEAuthData.Data = qeAuthData

	// There's no expected data size here, so the callee does the size check at the beginning.
	qeReportInnerCertData, err := parseQEReportInnerCertificationData(qeReportCertData[endQEAuthData:])
	if err != nil {
		return QEReportCertificationData{}, err
	}
	qeReport.CertificationData = qeReportInnerCertData

	return qeReport, nil
}

func parseQEReportInnerCertificationData(qeReportAuthDataCertData []byte) (CertificationData, error) {
	qeReportAuthDataCertDataLength := len(qeReportAuthDataCertData)
	if qeReportAuthDataCertDataLength <= 6 {
		return CertificationData{}, fmt.Errorf("QEReportCertificationData.CertificationData is too short to be parsed (received: %d bytes)", qeReportAuthDataCertDataLength)
	}
	qeAuthDataInnerCertData := CertificationData{
		Type:           binary.LittleEndian.Uint16(qeReportAuthDataCertData[0:2]),
		ParsedDataSize: binary.LittleEndian.Uint32(qeReportAuthDataCertData[2:6]),
	}

	endQEAuthDataInnerCertData := 6 + qeAuthDataInnerCertData.ParsedDataSize
	if int(endQEAuthDataInnerCertData) > qeReportAuthDataCertDataLength {
		return CertificationData{}, fmt.Errorf("QEReportCertificationData.CertificationData.ParsedDataSize is either incorrect or data is truncated (requires at least: %d bytes, left: %d bytes)", qeAuthDataInnerCertData.ParsedDataSize-6, qeReportAuthDataCertDataLength-6)
	}

	data := qeReportAuthDataCertData[6 : 6+qeAuthDataInnerCertData.ParsedDataSize]
	expectedParsedDataSize := int(qeAuthDataInnerCertData.ParsedDataSize)
	actualParsedDataSize := len(data)
	if expectedParsedDataSize != actualParsedDataSize {
		return CertificationData{}, fmt.Errorf("QEReportCertificationData.CertificationData.Data does not match the defined size (expected: %d bytes, got: %d bytes)", expectedParsedDataSize, actualParsedDataSize)
	}

	qeAuthDataInnerCertData.Data = data

	return qeAuthDataInnerCertData, nil
}