package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testTCBInfoJSON    = `{"id":"TDX","version":3,"issueDate":"2023-02-13T12:16:46Z","nextUpdate":"2023-03-15T12:16:46Z","fmspc":"00806f050000","pceId":"0000","tcbType":0,"tcbEvaluationDataNumber":14,"tdxModule":{"mrsigner":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","attributes":"0000000000000000","attributesMask":"FFFFFFFFFFFFFFFF"},"tcbLevels":[{"tcb":{"sgxtcbcomponents":[{"svn":5,"category":"BIOS","type":"Early Microcode Update"},{"svn":5,"category":"OS/VMM","type":"SGX Late Microcode Update"},{"svn":13,"category":"OS/VMM","type":"TXT SINIT"},{"svn":2,"category":"BIOS"},{"svn":3,"category":"BIOS"},{"svn":1,"category":"BIOS"},{"svn":0},{"svn":3,"category":"OS/VMM","type":"SEAMLDR ACM"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":11,"tdxtcbcomponents":[{"svn":3,"category":"OS/VMM","type":"TDX Module"},{"svn":0,"category":"OS/VMM","type":"TDX Module"},{"svn":5,"category":"OS/VMM","type":"TDX Late Microcode Update"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}]},"tcbDate":"2022-11-09T00:00:00Z","tcbStatus":"UpToDate"},{"tcb":{"sgxtcbcomponents":[{"svn":5,"category":"BIOS","type":"Early Microcode Update"},{"svn":5,"category":"OS/VMM","type":"SGX Late Microcode Update"},{"svn":13,"category":"OS/VMM","type":"TXT SINIT"},{"svn":2,"category":"BIOS"},{"svn":3,"category":"BIOS"},{"svn":1,"category":"BIOS"},{"svn":0},{"svn":3,"category":"OS/VMM","type":"SEAMLDR ACM"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":5,"tdxtcbcomponents":[{"svn":3,"category":"OS/VMM","type":"TDX Module"},{"svn":0,"category":"OS/VMM","type":"TDX Module"},{"svn":5,"category":"OS/VMM","type":"TDX Late Microcode Update"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}]},"tcbDate":"2018-01-04T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00106","INTEL-SA-00115","INTEL-SA-00135","INTEL-SA-00203","INTEL-SA-00220","INTEL-SA-00233","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477"]}]}`
	testQEIdentityJSON = `{"id":"TD_QE","version":2,"issueDate":"2023-02-13T12:16:46Z","nextUpdate":"2023-03-15T12:16:46Z","tcbEvaluationDataNumber":14,"miscselect":"00000000","miscselectMask":"FFFFFFFF","attributes":"11000000000000000000000000000000","attributesMask":"FBFFFFFFFFFFFFFF0000000000000000","mrsigner":"DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5","isvprodid":2,"tcbLevels":[{"tcb":{"isvsvn":4},"tcbDate":"2022-11-09T00:00:00Z","tcbStatus":"UpToDate"}]}`
)

func TestUnmarshalTCBInfo(t *testing.T) {
	assert := assert.New(t)

	var tcbInfo TCBInfo
	err := json.Unmarshal([]byte(testTCBInfoJSON), &tcbInfo)
	assert.NoError(err)
}

func TestUnmarshalQEIdentity(t *testing.T) {
	assert := assert.New(t)

	var qeIdentity QEIdentity
	err := json.Unmarshal([]byte(testQEIdentityJSON), &qeIdentity)
	assert.NoError(err)
}
