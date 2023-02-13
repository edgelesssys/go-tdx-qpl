package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testTCBInfoJSON    = `{"tcbInfo":{"id":"TDX","version":3,"issueDate":"2023-02-13T12:16:46Z","nextUpdate":"2023-03-15T12:16:46Z","fmspc":"00806f050000","pceId":"0000","tcbType":0,"tcbEvaluationDataNumber":14,"tdxModule":{"mrsigner":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","attributes":"0000000000000000","attributesMask":"FFFFFFFFFFFFFFFF"},"tcbLevels":[{"tcb":{"sgxtcbcomponents":[{"svn":5,"category":"BIOS","type":"Early Microcode Update"},{"svn":5,"category":"OS/VMM","type":"SGX Late Microcode Update"},{"svn":13,"category":"OS/VMM","type":"TXT SINIT"},{"svn":2,"category":"BIOS"},{"svn":3,"category":"BIOS"},{"svn":1,"category":"BIOS"},{"svn":0},{"svn":3,"category":"OS/VMM","type":"SEAMLDR ACM"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":11,"tdxtcbcomponents":[{"svn":3,"category":"OS/VMM","type":"TDX Module"},{"svn":0,"category":"OS/VMM","type":"TDX Module"},{"svn":5,"category":"OS/VMM","type":"TDX Late Microcode Update"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}]},"tcbDate":"2022-11-09T00:00:00Z","tcbStatus":"UpToDate"},{"tcb":{"sgxtcbcomponents":[{"svn":5,"category":"BIOS","type":"Early Microcode Update"},{"svn":5,"category":"OS/VMM","type":"SGX Late Microcode Update"},{"svn":13,"category":"OS/VMM","type":"TXT SINIT"},{"svn":2,"category":"BIOS"},{"svn":3,"category":"BIOS"},{"svn":1,"category":"BIOS"},{"svn":0},{"svn":3,"category":"OS/VMM","type":"SEAMLDR ACM"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":5,"tdxtcbcomponents":[{"svn":3,"category":"OS/VMM","type":"TDX Module"},{"svn":0,"category":"OS/VMM","type":"TDX Module"},{"svn":5,"category":"OS/VMM","type":"TDX Late Microcode Update"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}]},"tcbDate":"2018-01-04T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00106","INTEL-SA-00115","INTEL-SA-00135","INTEL-SA-00203","INTEL-SA-00220","INTEL-SA-00233","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477"]}]},"signature":"2982cdbaff03eccf79af180eb35a04fe8b7afd23b6ac564bdb1ce186831831235b26549e062a727cd647252ce21af28a603a8e494dccc4073c360389bd8864a0"}`
	testQEIdentityJSON = `{"enclaveIdentity":{"id":"TD_QE","version":2,"issueDate":"2023-02-13T12:16:46Z","nextUpdate":"2023-03-15T12:16:46Z","tcbEvaluationDataNumber":14,"miscselect":"00000000","miscselectMask":"FFFFFFFF","attributes":"11000000000000000000000000000000","attributesMask":"FBFFFFFFFFFFFFFF0000000000000000","mrsigner":"DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5","isvprodid":2,"tcbLevels":[{"tcb":{"isvsvn":4},"tcbDate":"2022-11-09T00:00:00Z","tcbStatus":"UpToDate"}]},"signature":"f9e4fdf2d8a8dd5c950cea3a10d2add9745154b1a3d5a7ba49e530bc6875da685610ebbb0cd8e3401866ce634101593f19e8a8cc0f725d06f3f5d0d3c5c880ba"}`
)

func TestUnmarshalTCBInfo(t *testing.T) {
	assert := assert.New(t)

	var jsonBlob struct {
		TCBInfo TCBInfo `json:"tcbInfo"`
	}
	err := json.Unmarshal([]byte(testTCBInfoJSON), &jsonBlob)
	assert.NoError(err)
}

func TestUnmarshalQEIdentity(t *testing.T) {
	assert := assert.New(t)

	var jsonBlob struct {
		QEIdentity QEIdentity `json:"enclaveIdentity"`
	}
	err := json.Unmarshal([]byte(testQEIdentityJSON), &jsonBlob)
	assert.NoError(err)
}
