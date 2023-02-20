package types

import (
	"encoding/json"
	"testing"

	"github.com/edgelesssys/go-tdx-qpl/blobs"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalTCBInfo(t *testing.T) {
	assert := assert.New(t)

	var tcbInfo struct {
		TCBInfo TCBInfo `json:"tcbInfo"`
	}
	err := json.Unmarshal(blobs.TCBInfoJSON, &tcbInfo)
	assert.NoError(err)
}

func TestUnmarshalQEIdentity(t *testing.T) {
	assert := assert.New(t)

	var qeIdentity struct {
		QEIdentity QEIdentity `json:"enclaveIdentity"`
	}
	err := json.Unmarshal(blobs.QEIdentityJSON, &qeIdentity)
	assert.NoError(err)
}
