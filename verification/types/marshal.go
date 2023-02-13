package types

import (
	"encoding/binary"
)

// Marshal serializes an EnclaveReport to its binary representation found in a Quote Enclave (QE) report or quote.
func (er *EnclaveReport) Marshal() [384]byte {
	miscSelect := make([]byte, 4)
	isvProdID := make([]byte, 2)
	isvSVN := make([]byte, 2)
	binary.LittleEndian.PutUint32(miscSelect, er.MiscSelect)
	binary.LittleEndian.PutUint16(isvProdID, er.ISVProdID)
	binary.LittleEndian.PutUint16(isvSVN, er.ISVSVN)

	var result [384]byte
	copy(result[0:16], er.CPUSVN[:])
	copy(result[16:20], miscSelect)
	copy(result[20:48], er.Reserved1[:])
	copy(result[48:64], er.Attributes[:])
	copy(result[64:96], er.MRENCLAVE[:])
	copy(result[96:128], er.Reserved2[:])
	copy(result[128:160], er.MRSIGNER[:])
	copy(result[160:256], er.Reserved3[:])
	copy(result[256:258], isvProdID)
	copy(result[258:260], isvSVN)
	copy(result[260:320], er.Reserved4[:])
	copy(result[320:384], er.ReportData[:])

	return result
}

// Marshal serializes an SGX/TDX Quote v4 header (SGXQuote4Header) into its binary representation typically found in a raw quote.
func (qh *SGXQuote4Header) Marshal() [48]byte {
	version := make([]byte, 2)
	attestationKeyType := make([]byte, 2)
	teeType := make([]byte, 4)
	reserved := make([]byte, 4)
	binary.LittleEndian.PutUint16(version, qh.Version)
	binary.LittleEndian.PutUint16(attestationKeyType, qh.AttestationKeyType)
	binary.LittleEndian.PutUint32(teeType, qh.TEEType)
	binary.LittleEndian.PutUint32(reserved, qh.Reserved)

	var result [48]byte
	copy(result[0:2], version)
	copy(result[2:4], attestationKeyType)
	copy(result[4:8], teeType)
	copy(result[8:12], reserved)
	copy(result[12:28], qh.VendorID[:])
	copy(result[28:48], qh.UserData[:])

	return result
}

// Marshal serializes an TDX TDReport (SGXReport2) into its binary representation typically found in a raw quote.
func (qr *SGXReport2) Marshal() [584]byte {
	seamAttributes := make([]byte, 8)
	tdAttributes := make([]byte, 8)
	xfam := make([]byte, 8)
	binary.LittleEndian.PutUint64(seamAttributes, qr.SEAMAttributes)
	binary.LittleEndian.PutUint64(tdAttributes, qr.TDAttributes)
	binary.LittleEndian.PutUint64(xfam, qr.XFAM)

	var result [584]byte
	copy(result[0:16], qr.TCBSVN[:])
	copy(result[16:64], qr.MRSEAM[:])
	copy(result[64:112], qr.MRSIGNERSEAM[:])
	copy(result[112:120], seamAttributes)
	copy(result[120:128], tdAttributes)
	copy(result[128:136], xfam)
	copy(result[136:184], qr.MRTD[:])
	copy(result[184:232], qr.MRCONFIG[:])
	copy(result[232:280], qr.MROWNER[:])
	copy(result[280:328], qr.MROWNERCONFIG[:])
	copy(result[328:376], qr.RTMR[:][0][:])
	copy(result[376:424], qr.RTMR[:][1][:])
	copy(result[424:472], qr.RTMR[:][2][:])
	copy(result[472:520], qr.RTMR[:][3][:])
	copy(result[520:584], qr.ReportData[:])

	return result
}
