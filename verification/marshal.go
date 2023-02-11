package verification

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
