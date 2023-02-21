package types

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/edgelesssys/go-tdx-qpl/verification/status"
)

const (
	// TCBInfoTDXID indicates that the TCB Info is for a TDX enclave.
	TCBInfoTDXID = "TDX"

	// TCBInfoSGXID indicates that the TCB Info is for a SGX enclave.
	TCBInfoSGXID = "SGX"

	// TCBInfoMinVersion is the minimal TCB version supporting TDX.
	TCBInfoMinVersion = 3

	// CPUSVNByteLen is the length of a CPU Security Version Number (SVN) in bytes.
	CPUSVNByteLen = 16

	// QEIdentityVersion is the pinned version of the QE Identity information returned by the PCE.
	QEIdentityVersion = 2

	// QEIdentityTDXID indicates that the QE Identity is for a TDX enclave.
	QEIdentityTDXID = "TD_QE"

	// PlatformIssuer is the CA issuer for multi platform PCK certificates.
	PlatformIssuer = "Intel SGX PCK Platform CA"

	// ProcessorIssuer is the CA issuer for single platform PCK certificates.
	ProcessorIssuer = "Intel SGX PCK Processor CA"
)

// TCBInfo contains expected Trusted Computing Base (TCB) information for a TDX enclave.
type TCBInfo struct {
	ID                      string     `json:"id"`
	Version                 uint32     `json:"version"`
	IssueDate               time.Time  `json:"issueDate"`
	NextUpdate              time.Time  `json:"nextUpdate"`
	FMSPC                   [6]byte    `json:"fmspc"`
	PCEID                   [2]byte    `json:"pceid"`
	TCBType                 int        `json:"tcbType"`
	TCBEvaluationDataNumber uint32     `json:"tcbEvaluationDataNumber"`
	TDXModule               TDXModule  `json:"tdxModule"`
	TCBLevels               []TCBLevel `json:"tcbLevels"`
}

// UnmarshalJSON parses a JSON representation of the TCB Info into a TCBInfo.
func (t *TCBInfo) UnmarshalJSON(data []byte) error {
	var tcbInfoJSON tcbInfoJSON
	if err := json.Unmarshal(data, &tcbInfoJSON); err != nil {
		return fmt.Errorf("unmarshaling TCB Info JSON: %w", err)
	}
	var err error

	t.ID = tcbInfoJSON.ID
	t.Version = tcbInfoJSON.Version

	t.IssueDate, err = time.Parse(time.RFC3339, tcbInfoJSON.IssueDate)
	if err != nil {
		return fmt.Errorf("parsing TCBInfo issue date: %w", err)
	}
	t.NextUpdate, err = time.Parse(time.RFC3339, tcbInfoJSON.NextUpdate)
	if err != nil {
		return fmt.Errorf("parsing TCBInfo next update date: %w", err)
	}

	fmspc, err := decodeHexToByte(tcbInfoJSON.FMSPC, 6)
	if err != nil {
		return fmt.Errorf("decoding FMSPC: %w", err)
	}
	t.FMSPC = [6]byte(fmspc)

	pceid, err := decodeHexToByte(tcbInfoJSON.PCEID, 2)
	if err != nil {
		return fmt.Errorf("decoding PCEID: %w", err)
	}
	t.PCEID = [2]byte(pceid)

	t.TCBType = tcbInfoJSON.TCBType
	t.TCBEvaluationDataNumber = tcbInfoJSON.TCBEvaluationDataNumber
	t.TDXModule = tcbInfoJSON.TDXModule
	t.TCBLevels = tcbInfoJSON.TCBLevels

	return nil
}

// tcbInfoJSON contains expected Trusted Computing Base (TCB) information for a TDX enclave.
// This is the JSON representation of the TCB Info using basic strings and ints.
type tcbInfoJSON struct {
	ID                      string     `json:"id"`
	Version                 uint32     `json:"version"`
	IssueDate               string     `json:"issueDate"`
	NextUpdate              string     `json:"nextUpdate"`
	FMSPC                   string     `json:"fmspc"`
	PCEID                   string     `json:"pceid"`
	TCBType                 int        `json:"tcbType"`
	TCBEvaluationDataNumber uint32     `json:"tcbEvaluationDataNumber"`
	TDXModule               TDXModule  `json:"tdxModule"`
	TCBLevels               []TCBLevel `json:"tcbLevels"`
}

// QEIdentity contains the expected information of the TDX Quoting Enclave (QE).
type QEIdentity struct {
	ID                      string     `json:"id"`
	Version                 uint32     `json:"version"`
	IssueDate               time.Time  `json:"issueDate"`
	NextUpdate              time.Time  `json:"nextUpdate"`
	TCBEvaluationDataNumber uint32     `json:"tcbEvaluationDataNumber"`
	MiscSelect              uint32     `json:"miscselect"`
	MiscSelectMask          uint32     `json:"miscselectMask"`
	Attributes              [16]byte   `json:"attributes"`
	AttributesMask          [16]byte   `json:"attributesMask"`
	MRSIGNER                [32]byte   `json:"mrSigner"`
	ISVProdID               uint16     `json:"isvprodid"`
	TCBLevels               []TCBLevel `json:"tcbLevels"`
}

// UnmarshalJSON parses a JSON representation of the QE Identity into a QEIdentity.
func (q *QEIdentity) UnmarshalJSON(data []byte) error {
	var qeIdentity qeIdentityJSON
	if err := json.Unmarshal(data, &qeIdentity); err != nil {
		return fmt.Errorf("unmarshaling QE Identity JSON: %w", err)
	}

	var err error
	q.ID = qeIdentity.ID
	q.Version = qeIdentity.Version
	q.IssueDate, err = time.Parse(time.RFC3339, qeIdentity.IssueDate)
	if err != nil {
		return fmt.Errorf("parsing QEIdentity issue date: %w", err)
	}
	q.NextUpdate, err = time.Parse(time.RFC3339, qeIdentity.NextUpdate)
	if err != nil {
		return fmt.Errorf("parsing QEIdentity next update date: %w", err)
	}
	q.TCBEvaluationDataNumber = qeIdentity.TCBEvaluationDataNumber

	miscSelect, err := decodeHexToByte(qeIdentity.MiscSelect, 4)
	if err != nil {
		return fmt.Errorf("decoding MiscSelect: %w", err)
	}
	q.MiscSelect = binary.LittleEndian.Uint32(miscSelect)
	miscSelectMask, err := decodeHexToByte(qeIdentity.MiscSelectMask, 4)
	if err != nil {
		return fmt.Errorf("decoding MiscSelectMask: %w", err)
	}
	q.MiscSelectMask = binary.LittleEndian.Uint32(miscSelectMask)

	attributes, err := decodeHexToByte(qeIdentity.Attributes, 16)
	if err != nil {
		return fmt.Errorf("decoding Attributes: %w", err)
	}
	q.Attributes = [16]byte(attributes)
	attributesMask, err := decodeHexToByte(qeIdentity.AttributesMask, 16)
	if err != nil {
		return fmt.Errorf("decoding AttributesMask: %w", err)
	}
	q.AttributesMask = [16]byte(attributesMask)

	mrSigner, err := decodeHexToByte(qeIdentity.MRSIGNER, 32)
	if err != nil {
		return fmt.Errorf("decoding MRSIGNER: %w", err)
	}
	q.MRSIGNER = [32]byte(mrSigner)

	q.ISVProdID = qeIdentity.ISVProdID

	q.TCBLevels = qeIdentity.TCBLevels

	return nil
}

// GetTCBStatus returns the TCB status from QEIdentity for the given ISV SVN.
func (i *QEIdentity) GetTCBStatus(isvSvn uint16) status.TCBStatus {
	for _, tcbLevel := range i.TCBLevels {
		if tcbLevel.TCB.ISVSVN == isvSvn {
			return tcbLevel.TCBStatus
		}
	}
	return status.Revoked
}

// qeIdentityJSON contains the expected information of the TDX Quoting Enclave (QE).
// This is the JSON representation of the TCB Info using basic strings and ints.
type qeIdentityJSON struct {
	ID                      string     `json:"id"`
	Version                 uint32     `json:"version"`
	IssueDate               string     `json:"issueDate"`
	NextUpdate              string     `json:"nextUpdate"`
	TCBEvaluationDataNumber uint32     `json:"tcbEvaluationDataNumber"`
	MiscSelect              string     `json:"miscselect"`
	MiscSelectMask          string     `json:"miscselectMask"`
	Attributes              string     `json:"attributes"`
	AttributesMask          string     `json:"attributesMask"`
	MRSIGNER                string     `json:"mrSigner"`
	ISVProdID               uint16     `json:"isvprodid"`
	TCBLevels               []TCBLevel `json:"tcbLevels"`
}

// TDXModule contains expected MRSIGNER and attribute information for a TDX enclave.
type TDXModule struct {
	MRSIGNERSEAM       [48]byte `json:"mrSigner"`
	SEAMAttributes     uint64   `json:"attributes"`
	SEAMAttributesMask uint64   `json:"attributesMask"`
}

// UnmarshalJSON parses a JSON representation of the TDX Module into a TDXModule.
func (t *TDXModule) UnmarshalJSON(data []byte) error {
	var tdxModule tdxModuleJSON
	if err := json.Unmarshal(data, &tdxModule); err != nil {
		return fmt.Errorf("unmarshaling TDX Module JSON: %w", err)
	}

	mrSigner, err := decodeHexToByte(tdxModule.MRSIGNERSEAM, 48)
	if err != nil {
		return fmt.Errorf("decoding MRSIGNER: %w", err)
	}
	t.MRSIGNERSEAM = [48]byte(mrSigner)

	attributes, err := decodeHexToByte(tdxModule.SEAMAttributes, 8)
	if err != nil {
		return fmt.Errorf("decoding Attributes: %w", err)
	}
	t.SEAMAttributes = binary.LittleEndian.Uint64(attributes)
	attributesMask, err := decodeHexToByte(tdxModule.SEAMAttributesMask, 8)
	if err != nil {
		return fmt.Errorf("decoding AttributeMask: %w", err)
	}
	t.SEAMAttributesMask = binary.LittleEndian.Uint64(attributesMask)

	return nil
}

// tdxModuleJSON contains expected MRSIGNER and attribute information for a TDX enclave.
// This is the JSON representation of the TCB Info using basic strings and ints.
type tdxModuleJSON struct {
	MRSIGNERSEAM       string `json:"mrSigner"`
	SEAMAttributes     string `json:"attributes"`
	SEAMAttributesMask string `json:"attributesMask"`
}

// TCBLevel contains expected TCB information for a TDX enclave.
type TCBLevel struct {
	TCB         TCB              `json:"tcb"`
	TCBDate     time.Time        `json:"tcbDate"`
	TCBStatus   status.TCBStatus `json:"tcbStatus"`
	AdvisoryIDs []string         `json:"advisoryIDs"`
}

// UnmarshalJSON parses a JSON representation of the TCB Level into a TCBLevel.
func (t *TCBLevel) UnmarshalJSON(data []byte) error {
	var tcbLevel tcbLevelJSON
	if err := json.Unmarshal(data, &tcbLevel); err != nil {
		return fmt.Errorf("unmarshaling TCB Level JSON: %w", err)
	}

	t.TCB = tcbLevel.TCB
	tcbDate, err := time.Parse(time.RFC3339, tcbLevel.TCBDate)
	if err != nil {
		return fmt.Errorf("parsing TCB Date: %w", err)
	}
	t.TCBDate = tcbDate
	t.TCBStatus = status.TCBStatus(tcbLevel.TCBStatus)
	t.AdvisoryIDs = tcbLevel.AdvisoryIDs

	return nil
}

// tcbLevelJSON contains expected TCB information for a TDX enclave.
// This is the JSON representation of the TCB Info using basic strings and ints.
type tcbLevelJSON struct {
	TCB         TCB      `json:"tcb"`
	TCBDate     string   `json:"tcbDate"`
	TCBStatus   string   `json:"tcbStatus"`
	AdvisoryIDs []string `json:"advisoryIDs"`
}

// TCB describes the TCB status of a TDX enclave.
type TCB struct {
	SGXTCBComponents [16]TCBComponent `json:"sgxtcbcomponents"`
	TDXTCBComponents [16]TCBComponent `json:"tdxtcbcomponents"`
	PCESVN           uint16           `json:"pcesvn"`
	ISVSVN           uint16           `json:"isvsvn"`
}

// TCBComponent describes SVN information for an SGX/TDX enclave.
type TCBComponent struct {
	SVN      uint8  `json:"svn"`
	Category string `json:"category"`
	Type     string `json:"type"`
}

// decodeHexToByte decodes a hex string into a byte array.
// This function errors if the decoded string is not the expected length,
// to save the caller from having to check the length when parsing into fixed-size arrays.
func decodeHexToByte(in string, expectedLen int) ([]byte, error) {
	out, err := hex.DecodeString(in)
	if err != nil {
		return nil, fmt.Errorf("decoding hex string: %w", err)
	}

	if len(out) != expectedLen {
		return nil, fmt.Errorf("expected %d bytes, but got %d", expectedLen, len(out))
	}

	return out, nil
}
