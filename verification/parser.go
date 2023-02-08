package verification

import (
	"encoding/binary"
)

/*
	TDX (SGX Quote 4 / SGX Report 2) Quote parser
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

	signatureLength := binary.LittleEndian.Uint32(rawQuote[632:636])

	return SGXQuote4{
		Header:          quoteHeader,
		Body:            body,
		SignatureLength: signatureLength,
		Signature:       rawQuote[636 : 636+signatureLength],
	}
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

func ParseSignature(signature []byte) ECDSA256QuoteV4AuthData {
	quoteSignature := ECDSA256QuoteV4AuthData{
		Signature: [64]byte(signature[0:64]),   // ECDSA256 signature
		PublicKey: [64]byte(signature[64:128]), // ECDSA256 public key
		CertificationData: CertificationData{
			Type:           binary.LittleEndian.Uint16(signature[128:130]),
			ParsedDataSize: binary.LittleEndian.Uint32(signature[130:134]),
		},
	}

	quoteSignature.CertificationData.Data = ParseQECertificationData(signature[134 : 134+quoteSignature.CertificationData.ParsedDataSize])

	return quoteSignature
}

func ParseQECertificationData(qeReportData []byte) QEReportCertificationData {
	qeReport := QEReportCertificationData{
		EnclaveReport: EnclaveReport{
			CPUSVN:     [16]byte(qeReportData[0:16]),
			MiscSelect: binary.LittleEndian.Uint32(qeReportData[16:20]),
			Reserved1:  [28]byte(qeReportData[20:48]),
			Attributes: [16]byte(qeReportData[48:64]),
			MRENCLAVE:  [32]byte(qeReportData[64:96]),
			Reserved2:  [32]byte(qeReportData[96:128]),
			MRSIGNER:   [32]byte(qeReportData[128:160]),
			Reserved3:  [96]byte(qeReportData[160:256]),
			isvProdID:  binary.LittleEndian.Uint16(qeReportData[256:258]),
			isvSVN:     binary.LittleEndian.Uint16(qeReportData[258:260]),
			Reserved4:  [60]byte(qeReportData[260:320]),
			ReportData: [64]byte(qeReportData[320:384]),
		},
		Signature: [64]byte(qeReportData[384:448]),
		QEAuthData: QEAuthData{
			ParsedDataSize: binary.LittleEndian.Uint16(qeReportData[448:450]),
		},
	}

	endQEAuthData := 450 + qeReport.QEAuthData.ParsedDataSize
	qeReport.QEAuthData.Data = qeReportData[450:endQEAuthData]
	qeReport.CertificationData = ParseQEAuthDataCertificationData(qeReportData[endQEAuthData:])

	return qeReport
}

func ParseQEAuthDataCertificationData(qeReportAuthDataCertData []byte) CertificationData {
	qeAuthDataCertData := CertificationData{
		Type:           binary.LittleEndian.Uint16(qeReportAuthDataCertData[0:2]),
		ParsedDataSize: binary.LittleEndian.Uint32(qeReportAuthDataCertData[2:6]),
	}

	data := qeReportAuthDataCertData[6 : 6+qeAuthDataCertData.ParsedDataSize]
	qeAuthDataCertData.Data = data

	return qeAuthDataCertData
}
